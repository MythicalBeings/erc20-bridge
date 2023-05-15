/*
 * Copyright © 2021 Jelurida IP B.V.
 *
 * See the LICENSE.txt file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with Jelurida B.V.,
 * no part of this software, including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE.txt file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */

package com.jelurida.ardor.contracts.interchain.eth;

import com.jelurida.web3j.erc20.utils.ErrorMsg;
import com.jelurida.web3j.generated.IERC20;
import com.jelurida.web3j.erc20.utils.TransactionalContract;
import com.jelurida.web3j.erc20.utils.Utils;
import com.jelurida.web3j.erc20.utils.protocol.AlchemyHttpService;
import com.jelurida.web3j.erc20.utils.txman.RetryFeeProvider;
import com.jelurida.web3j.erc20.utils.txman.RetryingRawTransactionManager;
import nxt.Constants;
import nxt.Nxt;
import nxt.account.Account;
import nxt.addons.*;
import nxt.ae.AssetExchangeTransactionType;
import nxt.blockchain.ChildChain;
import nxt.crypto.Crypto;
import nxt.crypto.EncryptedData;
import nxt.http.callers.*;
import nxt.http.responses.BlockResponse;
import nxt.util.Convert;
import nxt.util.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.EventValues;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.Transfer;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import static nxt.util.JSON.jsonArrayCollector;

public class AssetsErc20 extends AbstractContract<Object, Object> {

    public static final int DEFAULT_CHILD_BLOCK_DEADLINE = 10 * 60;
    public static final int UNCONFIRMED_TX_RETRY_MILLIS = Constants.isTestnet && Constants.isAutomatedTest ? 5000 : 15000;
    public static final int ARDOR_BLOCK_TIME = Constants.isTestnet ? (Constants.isAutomatedTest ? 1 : Constants.BLOCK_TIME / Constants.TESTNET_ACCELERATION) : Constants.BLOCK_TIME;
    public static final String CONTRACT_ADDRESS_MISSING_ERROR = "contractAddress missing - Please config in contractRunner";
    public static final long ETH_BLOCK_TIME_ESTIMATION_EXPIRATION = 360 * 60;
    public static final BigInteger ETH_BLOCK_TIME_ESTIMATION_BLOCK_COUNT = BigInteger.valueOf(1000);
    public static final int DEFAULT_ETH_BLOCK_TIME = 2000;
    public static final long ETH_GAS_PRICE_ESTIMATION_EXPIRATION = 60 * 60;
    private final PegContext pegContext = new PegContext();

    private static final BigDecimal QNT_FACTOR = new BigDecimal("100000000");
    private static final BigInteger QNT_FACTOR_INT = new BigInteger("100000000");

    private ExecutorService threadPool;
    private final ConcurrentLinkedDeque<JO> wrappingLog = new ConcurrentLinkedDeque<>();
    private int lastUnwrapHeight;

    @ContractParametersProvider
    public interface Parameters {
        @ContractRunnerParameter
        @ContractSetupParameter
        String apiUrl();

        @ContractRunnerParameter
        @ContractSetupParameter
        long chainId();

        /**
         * Size of the block range when calling eth_getLogs.
         * Value of 0 makes all eth_getLogs requests to be executed from the first to the latest block in the blockchain.
         * Make sure that ethLogsBlockRange * ethLogsIterations is at least few hours to allow the user process unwraps
         *
         * @return Number of blocks
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default int ethLogsBlockRange() {
            return 10000;
        }

        /**
         * Some services have a strict limit on the block range of requests which get logs, so we need to execute
         * several requests in order to get the logs from the desired range. This configuration controls how many pieces
         * of the block range will be requested
         *
         * @return Number of repetitions of the requests for getting logs
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default int ethLogsIterations() {
            return 1;
        }

        @ContractRunnerParameter
        @ContractSetupParameter
        default int ardorConfirmations() {
            return 1;
        }

        /**
         * Percentage to overpay in fee when issuing Ardor transactions
         *
         * @return Percentage from 0 to 100. May be negative too
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default String ardorInitialFeeOverpayPercent() {
            return "0";
        }

        /**
         * If an Ardor transaction fails to be accepted in a block until it's expiration time, the transaction is
         * recreated with higher fee. The fee is increased with the percentage returned by this configuration
         *
         * @return Percentage from 0 to 100
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default int ardorRetryFeeOverpayPercent() {
            return 15;
        }

        @ContractRunnerParameter
        @ContractSetupParameter
        default int ethereumConfirmations() {
            return 1;
        }

        /**
         * Seconds before we give up waiting for the ethereum transaction to be accepted in a block and retry with
         * higher fee
         *
         * @return Time in seconds
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default long ethereumRetryTimeout() {
            return 60;
        }

        /**
         * Percentage to overpay in fee when issuing eth transactions
         *
         * @return Percentage from 0 to 100. May be negative too
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default String ethereumGasPriceInitialOverpay() {
            return "0";
        }

        /**
         * If an Ethereum transaction fails to be accepted in a block after {@link #ethereumRetryTimeout()}, the
         * transaction is replaced with another transaction which pays higher fee. This configuration controls how much
         * to increase the fee with each retry. The fee will be increased also for all other transactions for the next
         * {@link #ETH_GAS_PRICE_ESTIMATION_EXPIRATION} seconds
         *
         * @return Percentage from 0 to 100
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default int ethereumGasPriceRetryOverpay() {
            return 15;
        }

        @ContractRunnerParameter
        String ethereumBlockedAccountSecret();

        /**
         * A secret concatenated to the Ardor account public key in order to deterministically get the
         * credentials of an Ethereum deposit account dedicated to the owner of the public key
         *
         * @return Secret string. Use at least 160 bits of entropy
         */
        @ContractRunnerParameter
        String ethereumDepositAccountsSecret();

        /**
         * The contract address which will be managing the tokens on ethereum side. Must implement
         *
         * @return Ethereum address - string in format '0x' followed by 20 bytes in hex format (40 characters)
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        String contractAddress();

        @ContractRunnerParameter
        @ContractSetupParameter
        String assetId();

    }

    @Override
    public void init(InitializationContext context) {
        lastUnwrapHeight = context.getBlockchainHeight();
        threadPool = Executors.newCachedThreadPool();
        Parameters params = context.getParams(Parameters.class);
        pegContext.init(params, threadPool);
        Logger.logInfoMessage("MB-ERC20 | INIT | pegContext init!");
        if (pegContext.initializationError != null) {
            Logger.logErrorMessage("Peg initialization error " + pegContext.initializationError);
        }
    }

    @Override
    public void shutdown(ShutdownContext context) {
        context.shutdown(threadPool);
    }

    @Override
    public JO processRequest(RequestContext context) {
        Parameters params = context.getParams(Parameters.class);
        JO response = new JO();
        String contractParamsStr = context.getParameter("setupParams");
        JO requestParams = null;
        if (contractParamsStr != null) {
            requestParams = JO.parse(contractParamsStr);
        }

        String command = getParameter(context, requestParams, "command");
        if (command == null)
            return context.generateErrorResponse(10001, "MB-ERC20: Please specify a 'command' parameter");

        if (pegContext.initializationError != null)
            return context.generateErrorResponse(10004, "MB-ERC20: Peg initialization error " + pegContext.initializationError);

        String ardorRecipientPublicKey;

        switch (command) {
            case "getPegAddresses":
                response.put("ethereumBlockedAccount", pegContext.ethBlockedAccount.getAddress());
                response.put("ardorBlockedAccount", context.getAccountRs());
                break;
            case "mbGetContractAddress":
                response.put("contractAddress", pegContext.params.contractAddress());
                break;
            case "mbGetWrapDepositAddress":
                ardorRecipientPublicKey = getArdorRecipientPublicKeyParameter(context, requestParams);
                if (ardorRecipientPublicKey == null)
                    return context.getResponse();
                response.put("depositAddress", getWrapDepositAccount(params, ardorRecipientPublicKey).getAddress());
                break;
            case "mbProcessWrapsForAccount":
                ardorRecipientPublicKey = getArdorRecipientPublicKeyParameter(context, requestParams);
                if (ardorRecipientPublicKey == null)
                    return context.getResponse();
                return mbProcessWrapsForAccount(context, ardorRecipientPublicKey);
            case "mbProcessUnwrapsAtHeight":
                String heightStr = getParameter(context, requestParams, "height");
                if (heightStr == null)
                    return context.generateErrorResponse(10001, "Please specify a 'height' parameter");
                return mbProcessUnwrapsAtHeight(context, Integer.parseInt(heightStr));
            case "mbGetUnwrappingLog":
                response.put("log", wrappingLog.stream().collect(jsonArrayCollector()));
                break;
            case "secretToEthPrivateKey":
                String secret = getParameter(context, requestParams, "secret");
                if (secret == null)
                    return context.generateErrorResponse(10001, "Please specify a 'secret' parameter");
                Credentials credentials = getCredentialsFromSecret(secret);
                response.put("address", credentials.getAddress());
                response.put("privateKeyNumeric", credentials.getEcKeyPair().getPrivateKey().toString());
                response.put("privateKeyHex", Numeric.encodeQuantity(credentials.getEcKeyPair().getPrivateKey()));
                break;
            default:
                throw new IllegalArgumentException(String.format("Invalid command parameter: %s", command));
        }
        return response;
    }

    @Override
    public JO processBlock(BlockContext context) {
        if (pegContext.initializationError != null) {
            return context.generateErrorResponse(10004, "MB-ERC20 | processBlock | Peg not initialized " + pegContext.initializationError);
        }
        Parameters params = context.getParams(Parameters.class);
        BlockResponse block = context.getBlock();
        if (!Constants.isAutomatedTest && block.getTimestamp() < Nxt.getEpochTime() - ARDOR_BLOCK_TIME * params.ardorConfirmations()) {
            return context.generateInfoResponse("MB-ERC20 | processBlock | Block too old - " + new Date(Convert.fromEpochTime(block.getTimestamp())));
        }
        int height = context.getHeight();
        if (height > lastUnwrapHeight) {
            lastUnwrapHeight = height;
            return mbProcessUnwrapsAtHeight(context, height - params.ardorConfirmations());
        } else {
            return context.generateInfoResponse("MB-ERC20 | processBlock | Height already processed or before contract initialization: " + height);
        }
    }

    private JO mbProcessUnwrapsAtHeight(AbstractContractContext context, int height) {
        if (height <= 0 || height > context.getBlockchainHeight())
            return context.generateErrorResponse(10003, "MB-ERC20 | mbProcessUnwrapsAtHeight | Invalid height " + height);

        if (pegContext.initializationError != null)
            return context.generateErrorResponse(10004, "MB-ERC20 | mbProcessUnwrapsAtHeight | Peg initialization error " + pegContext.initializationError);

        try {
            JO result = new JO();
            JA transactionsLog = new JA();
            result.put("transactionsLog", transactionsLog);
            JO executed = GetExecutedTransactionsCall.create(ChildChain.IGNIS.getId())
                    .recipient(context.getAccountRs())
                    .type(AssetExchangeTransactionType.ASSET_TRANSFER.getType())
                    .subtype(AssetExchangeTransactionType.ASSET_TRANSFER.getSubtype())
                    .height(height).callNoError();
            for (JO transaction : executed.getJoList("transactions")) {
                JO log = mbProcessUnwrapTransaction(context, transaction);
                if (log != null) {
                    wrappingLog.add(log);
                    transactionsLog.add(log);
                }
            }
            return result;
        } catch (Throwable t) {
            context.logErrorMessage(t);
            return context.generateErrorResponse(10500, t.getMessage());
        }
    }

    @NotNull
    private JO mbProcessUnwrapTransaction(AbstractContractContext context, JO transaction) {
        JO result = new JO();
        try {
            String fullHash = transaction.getString("fullHash");
            result.put("fullHash", fullHash);
            JO messageJo = ReadMessageCall.create().chain(ChildChain.IGNIS.getId())
                    .transactionFullHash(fullHash)
                    .retrieve(false)
                    .privateKey(context.getConfig().getPrivateKey())
                    .call();

            if (messageJo.containsKey("errorDescription")) {
                result.put("error", "Cannot read transaction message: " + messageJo.get("errorDescription"));
                return result;
            }

            String recipientAddress = messageJo.getString("decryptedMessage");
            if (recipientAddress == null) {
                recipientAddress = messageJo.getString("message");
            }

            if (recipientAddress == null) {
                result.put("error", "message");
                return result;
            }

            Logger.logInfoMessage("MB-ERC20 | mbProcessUnwrapTransaction | recipientAddress: " + recipientAddress);

            if (Numeric.cleanHexPrefix(recipientAddress).length() > Address.MAX_BYTE_LENGTH * 2
                    || !recipientAddress.equalsIgnoreCase(Keys.toChecksumAddress(recipientAddress))) {
                result.put("error", "MB-ERC20 | mbProcessUnwrapTransaction | Invalid address in transaction message: " + recipientAddress);
                return result;
            }

            JO attachment = transaction.getJo("attachment");
            String assetIdStr = attachment.getString("asset");
            long assetId = Long.parseUnsignedLong(assetIdStr);
            String tokenAddress = pegContext.params.contractAddress();
            Logger.logInfoMessage("MB-ERC20 | mbProcessUnwrapTransaction | tokenAddress: " + tokenAddress + " | " + assetIdStr);

            if (tokenAddress != null) {
                //check the asset here too because during initialization the blockchain might not have been up-to date
                if (!pegContext.validateAsset(assetId, true)) {
                    throw new RuntimeException("MB-ERC20 | mbProcessUnwrapTransaction | Found invalid asset: " + pegContext.initializationError);
                }

                BigInteger amountToTransfer = new BigInteger((String) attachment.get("quantityQNT"));

                BigInteger height = pegContext.web3j.ethBlockNumber().send().getBlockNumber();
                List<Log> logs = getTransfersLogs(pegContext, height, pegContext.ethBlockedAccount.getAddress(), recipientAddress, null);

                Log logFromExistingWrap = logs.stream()
                        .filter(log -> mbIsExistingWrappingLog(context, log, amountToTransfer, fullHash))
                        .findAny()
                        .orElse(null);

                if (logFromExistingWrap != null) {
                    result.put("error", "MB-ERC20 | mbProcessUnwrapTransaction | Transfer already processed " + logFromExistingWrap);
                    return result;
                }

                BigDecimal amountToTransferDecimal = new BigDecimal(amountToTransfer);
                String parseAmountToTransfer = (amountToTransferDecimal.divide(QNT_FACTOR)).toString();
                BigInteger amountInETH = org.web3j.utils.Convert.toWei(parseAmountToTransfer, org.web3j.utils.Convert.Unit.ETHER).toBigIntegerExact();
                Logger.logInfoMessage("MB-ERC20 | mbProcessUnwrapTransaction | recipientAddress: " + recipientAddress + " | amountToTransfer: " + amountToTransfer + " parseAmountToTransfer: " + parseAmountToTransfer + " | Parse value: " + amountInETH);

                StaticGasProvider depositContractGasProvider = new DefaultGasProvider();
                IERC20 contractByDepositAccount = IERC20.load(pegContext.params.contractAddress(),
                        pegContext.web3j,
                        pegContext.ebaTransactionManager,
                        depositContractGasProvider);

                TransactionReceipt emptyReceipt = contractByDepositAccount.transfer(recipientAddress, amountInETH).send();

                pegContext.ebaTransactionManager.setCallbacks(emptyReceipt, (tr, r) -> {
                    logTransactionReceipt("MB-ERC20 | mbProcessUnwrapTransaction | Unwapping complete ", tr.getTransactionHash());
                    result.put("success", tr.getTransactionHash());
                }, (error) -> {
                    logTransactionReceipt("MB-ERC20 | mbProcessUnwrapTransaction | Unwapping error ", error);
                    result.put("error", error);
                });
            } else {
                result.put("error", "MB-ERC20 | mbProcessUnwrapTransaction | Transfers unknown asset " + assetIdStr);
            }
        } catch (Exception e) {
            context.logErrorMessage(e);
            result.put("error", "MB-ERC20 | mbProcessUnwrapTransaction | ERROR EXCEPTION: " + e.getMessage());
        }
        return result;
    }

    private boolean mbIsExistingWrappingLog(AbstractContractContext context, Log log,
                                            BigInteger amount, String wrapTriggeringFullHash) {

        if (!isTransferTokenAndAmountEqual(log, amount))
            return false;

        Transaction tx = getEthTransactionByHash(pegContext.web3j, log.getTransactionHash());
        byte[] transferData = Utils.getSafeTransferData(tx);

        if (transferData != null && transferData.length > 32) {
            EncryptedData encryptedData = EncryptedData.readEncryptedData(transferData);
            byte[] bytes = context.getConfig().decryptFrom(context.getPublicKey(), encryptedData, false);
            return wrapTriggeringFullHash.equals(Convert.toHexString(bytes));
        } else {
            return false;
        }
    }

    private static boolean isTransferTokenAndAmountEqual(Log log, BigInteger amount) {
        EventValues eventValues = Contract.staticExtractEventParameters(IERC20.TRANSFER_EVENT, log);
        BigInteger logAmount = Utils.getEventValueBigInteger(eventValues, 0);
        Boolean amountCheck = amount.equals(logAmount);
        return amountCheck;
    }

    private static Transaction getEthTransactionByHash(Web3j web3j, String transactionHash) {
        EthTransaction ethTransactionOrError;
        try {
            ethTransactionOrError = web3j.ethGetTransactionByHash(transactionHash).send();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (ethTransactionOrError.hasError()) {
            throw new RuntimeException("MB-ERC20 | getEthTransactionByHash | Error: " + ethTransactionOrError.getError());
        }
        return ethTransactionOrError.getTransaction().orElseThrow(() -> new RuntimeException("B-ERC20 | getEthTransactionByHash | Error: ethGetTransactionByHash returned null"));
    }

    private JO mbProcessWrapsForAccount(RequestContext context, String recipientPublicKey) {
        try {
            JO response = new JO();
            Parameters params = context.getParams(Parameters.class);
            Credentials depositAccount = getWrapDepositAccount(params, recipientPublicKey);
            if (pegContext == null) {
                Logger.logInfoMessage("MB-ERC20 | mbProcessWrapsForAccount | ERROR: pegContext is null");
                return context.generateResponse(response);
            }

            BigInteger height = pegContext.web3j.ethBlockNumber().send().getBlockNumber();

            String depositAccountAddress = depositAccount.getAddress();

            Logger.logInfoMessage("MB-ERC20 | mbProcessWrapsForAccount | depositAccount: " + depositAccountAddress + " | height: " + height);


            StaticGasProvider depositContractGasProvider = new DefaultGasProvider();

            RetryingRawTransactionManager depositAccountTransactionManager =
                    pegContext.createTransactionManager(pegContext.params, depositAccount, true);

            IERC20 contractByDepositAccount = IERC20.load(pegContext.params.contractAddress(),
                    pegContext.web3j,
                    depositAccountTransactionManager,
                    depositContractGasProvider);

            BigInteger balance = contractByDepositAccount.balanceOf(depositAccountAddress).send();

            if (balance.compareTo(BigInteger.ZERO) <= 0) {
                Logger.logInfoMessage("MB-ERC20 | mbProcessWrapsForAccount | BALANCE ZERO | Address " + depositAccountAddress + " | Request wrap at height " + height + " | Balance: " + balance);
                return context.generateResponse(response);
            }

            String id = depositAccountAddress;

            mbWrapTask task = pegContext.wrapTasks.putIfAbsent(id, new mbWrapTask(pegContext, context.getConfig(), id,
                    pegContext.params.contractAddress(), balance, height,
                    depositAccount, recipientPublicKey));

            if (task == null) {
                Logger.logInfoMessage("MB-ERC20 | mbProcessWrapsForAccount | Wrap task " + id + " started at height " + height);
                pegContext.wrapTasks.get(id).scheduleExecution();
                incrementResponseCounter(response, "starts");
            } else {
                Logger.logInfoMessage("MB-ERC20 | mbProcessWrapsForAccount | Wrap task " + id + " " + "skippedAlreadyRunning at height " + height);
                incrementResponseCounter(response, "skippedAlreadyRunning");
            }

            return context.generateResponse(response);

        } catch (Exception e) {
            context.logErrorMessage(e);
            return context.generateErrorResponse(10500, "" + e);
        }
    }

    @NotNull
    private static List<Log> getTransfersLogs(PegContext pegContext, BigInteger lastHeight,
                                              String from, String to, String value) throws IOException {
        DefaultBlockParameter fromBlock;
        DefaultBlockParameter toBlock;
        int blockRange = pegContext.params.ethLogsBlockRange();
        int iterations = pegContext.params.ethLogsIterations();

        List<Log> result = new ArrayList<>();
        while (iterations > 0) {
            if (blockRange > 0) {
                fromBlock = DefaultBlockParameter.valueOf(lastHeight.subtract(BigInteger.valueOf(blockRange - 1)));
                toBlock = DefaultBlockParameter.valueOf(lastHeight);
                lastHeight = lastHeight.subtract(BigInteger.valueOf(blockRange));
                iterations--;
            } else {
                fromBlock = DefaultBlockParameterName.EARLIEST;
                toBlock = DefaultBlockParameterName.LATEST;
                iterations = 0;
            }

            EthFilter filter = new EthFilter(
                    fromBlock,
                    toBlock,
                    pegContext.params.contractAddress())
                    //event
                    .addSingleTopic(EventEncoder.encode(IERC20.TRANSFER_EVENT));

            if (from == null) {
                filter.addNullTopic();
            } else {
                filter.addSingleTopic("0x" + TypeEncoder.encode(new Address(from)));
            }

            if (to == null) {
                filter.addNullTopic();
            } else {
                filter.addSingleTopic("0x" + TypeEncoder.encode(new Address(to)));
            }

            if (value == null) {
                filter.addNullTopic();
            } else {
                filter.addSingleTopic(TypeEncoder.encode(new Address(value)));
            }

            EthLog ethLog = pegContext.web3j.ethGetLogs(filter).send();
            if (ethLog.hasError()) {
                throw new RuntimeException("ethGetLogs failed: " + ethLog.getError().getMessage());
            } else {
                @SuppressWarnings("unchecked")
                List<EthLog.LogResult<Log>> logs = (List<EthLog.LogResult<Log>>) ((List<?>) ethLog.getLogs());
                logs.stream().map(EthLog.LogResult::get).forEach(result::add);
            }
        }
        return result;
    }

    private void incrementResponseCounter(JO response, String key) {
        response.put(key, response.getInt(key, 0) + 1);
    }

    @NotNull
    private Credentials getWrapDepositAccount(Parameters params, String publicKey) {
        return getCredentialsFromSecret(getUnwrapDepositAccSecret(params.ethereumDepositAccountsSecret(), publicKey));
    }

    @NotNull
    static String getUnwrapDepositAccSecret(String ethereumDepositAccountsSecret, String publicKey) {
        return ethereumDepositAccountsSecret + publicKey;
    }

    @NotNull
    static Credentials getCredentialsFromSecret(String secret) {
        return Credentials.create(ECKeyPair.create(Hash.sha256(secret.getBytes(StandardCharsets.UTF_8))));
    }

    static void logTransactionReceipt(String message, String transactionHash) {
        Logger.logInfoMessage(message + ": " + transactionHash);
        //" https://mumbai.polygonscan.com/tx/" + transactionHash);
    }

    private String getParameter(RequestContext context, JO requestParams, String name) {
        if (requestParams != null) {
            Object obj = requestParams.get(name);
            if (obj != null) {
                return obj.toString();
            }
        }
        return context.getParameter(name);
    }

    @Nullable
    private String getArdorRecipientPublicKeyParameter(RequestContext context, JO requestParams) {
        String ardorRecipientPublicKey = getParameter(context, requestParams, "ardorRecipientPublicKey");
        if (ardorRecipientPublicKey == null) {
            context.generateErrorResponse(10001, "Please specify a 'ardorRecipientPublicKey' parameter");
            return null;
        }
        if (!Crypto.isCanonicalPublicKey(Convert.parseHexString(ardorRecipientPublicKey))) {
            context.generateErrorResponse(10002, "Non-canonical public key: '" + ardorRecipientPublicKey + "'");
            return null;
        }
        return ardorRecipientPublicKey;
    }

    public static class PegContext implements RetryFeeProvider {
        private String initializationError = null;
        private Credentials ethBlockedAccount;
        private final Map<Long, JO> assetInfo = new HashMap<>();
        private Parameters params;
        private Web3j web3j;
        private ExecutorService executor;
        private long ethBlockTimeEstimation = DEFAULT_ETH_BLOCK_TIME;
        private long lastEthBlockTimeEstimationTime = 0;
        private BigInteger ethGasPrice = null;
        private long lastEthGasPriceEstimationTime = 0;
        private RetryingRawTransactionManager ebaTransactionManager;
        private final ConcurrentHashMap<String, mbWrapTask> wrapTasks = new ConcurrentHashMap<>();

        public PegContext() {
        }

        public void init(Parameters params, ExecutorService executor) {
            this.executor = executor;
            initializationError = null;
            if (Convert.emptyToNull(params.ethereumBlockedAccountSecret()) == null) {
                initializationError = "ethereumBlockedAccountSecret missing";
                return;
            }
            if (Convert.emptyToNull(params.ethereumDepositAccountsSecret()) == null) {
                initializationError = "ethereumDepositAccountsSecret missing";
                return;
            }

            if (Convert.emptyToNull(params.contractAddress()) == null) {
                initializationError = "contractAddress missing";
                return;
            }

            if (Convert.emptyToNull(params.assetId()) == null) {
                initializationError = "assetId missing";
                return;
            }

            if (initializationError != null) {
                return;
            }
            web3j = Web3j.build(new AlchemyHttpService(params.apiUrl()));
            this.params = params;
            ethBlockedAccount = getCredentialsFromSecret(params.ethereumBlockedAccountSecret());
            ebaTransactionManager = createTransactionManager(params, ethBlockedAccount, true);
            if (Convert.emptyToNull(params.contractAddress()) == null) {
                initializationError = CONTRACT_ADDRESS_MISSING_ERROR;
            }
        }

        @NotNull
        private RetryingRawTransactionManager createTransactionManager(Parameters params, Credentials account, boolean isAsyncReceiptProcessor) {
            int attempts = (int) ((params.ethereumRetryTimeout() * 1000L) / TransactionManager.DEFAULT_POLLING_FREQUENCY);
            return RetryingRawTransactionManager.create(web3j, account, params.chainId(),
                    attempts, TransactionManager.DEFAULT_POLLING_FREQUENCY, isAsyncReceiptProcessor,
                    this);
        }

        private boolean validateAsset(Long assetId, boolean checkExisting) {
            JO asset = getAssetInfo(assetId);
            if (asset != null) {
                if (asset.getInt("decimals") != 8) {
                    initializationError = "Asset " + Long.toUnsignedString(assetId) + " need 8 decimals.";
                    return false;
                }
                return true;
            } else {
                return !checkExisting;
            }
        }

        @Nullable
        private JO getAssetInfo(Long assetId) {
            return assetInfo.computeIfAbsent(assetId, id -> {
                JO assetResult = GetAssetCall.create().asset(id).call();
                if (assetResult.get("errorDescription") == null) {
                    return assetResult;
                } else {
                    return null;
                }
            });
        }

        public synchronized long getEthBlockDuration() throws IOException {
            long now = System.currentTimeMillis();
            if (now - lastEthBlockTimeEstimationTime > ETH_BLOCK_TIME_ESTIMATION_EXPIRATION * 1000) {
                ethBlockTimeEstimation = estimateEthBlockTime();
                Logger.logInfoMessage("MB-ERC20 | getEthBlockDuration | ethBlockTimeEstimation: " + ethBlockTimeEstimation);
                lastEthBlockTimeEstimationTime = now;
            }
            return ethBlockTimeEstimation;
        }

        public synchronized BigInteger getEthGasPrice() throws IOException {
            long now = System.currentTimeMillis();
            if (ethGasPrice == null || now - lastEthGasPriceEstimationTime > ETH_GAS_PRICE_ESTIMATION_EXPIRATION * 1000) {
                BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
                int overpayPercentage = Integer.parseInt(params.ethereumGasPriceInitialOverpay());
                BigInteger initialOverpay = gasPrice.multiply(BigInteger.valueOf(overpayPercentage)).
                        divide(BigInteger.valueOf(100));
                ethGasPrice = gasPrice.add(initialOverpay);
                Logger.logInfoMessage("MB-ERC20 | getEthGasPrice | ethGasPrice=" + gasPrice + "+(" + initialOverpay + ")=" + ethGasPrice);
                lastEthGasPriceEstimationTime = now;
            }
            return ethGasPrice;
        }

        @Override
        public synchronized BigInteger getNewGasPrice(BigInteger failedTransactionGasPrice) {
            BigInteger gasPriceIncrease = failedTransactionGasPrice.
                    multiply(BigInteger.valueOf(params.ethereumGasPriceRetryOverpay())).divide(BigInteger.valueOf(100));

            BigInteger increasedPrice = failedTransactionGasPrice.add(gasPriceIncrease);

            if (increasedPrice.compareTo(ethGasPrice) > 0) {
                Logger.logInfoMessage("MB-ERC20 | getNewGasPrice | Increasing gas price: " + failedTransactionGasPrice + "+" + gasPriceIncrease +
                        "=" + increasedPrice + " > " + ethGasPrice);
                ethGasPrice = increasedPrice;
                lastEthGasPriceEstimationTime = System.currentTimeMillis();
            } else {
                increasedPrice = ethGasPrice;
            }
            return increasedPrice;
        }

        private long estimateEthBlockTime() throws IOException {
            EthBlock ethBlockResult = web3j.ethGetBlockByNumber(
                    DefaultBlockParameterName.LATEST, false).send();
            if (ethBlockResult.hasError()) {
                Logger.logErrorMessage("MB-ERC20 | estimateEthBlockTime | Get latest block failed " + ethBlockResult.getError());
                return DEFAULT_ETH_BLOCK_TIME;
            }
            EthBlock.Block latest = ethBlockResult.getBlock();
            long now = Utils.timestampToMillis(latest.getTimestamp());
            BigInteger currentHeight = latest.getNumber();
            BigInteger oldHeight = currentHeight.subtract(ETH_BLOCK_TIME_ESTIMATION_BLOCK_COUNT);

            ethBlockResult = web3j.ethGetBlockByNumber(
                    DefaultBlockParameter.valueOf(oldHeight), false).send();

            if (ethBlockResult.hasError()) {
                Logger.logErrorMessage("MB-ERC20 | estimateEthBlockTime | Get block " + oldHeight
                        + " failed " + ethBlockResult.getError());
                return DEFAULT_ETH_BLOCK_TIME;
            }

            long result = (now - Utils.timestampToMillis(ethBlockResult.getBlock().getTimestamp())) / ETH_BLOCK_TIME_ESTIMATION_BLOCK_COUNT.longValueExact();
            Logger.logInfoMessage("MB-ERC20 | estimateEthBlockTime | Ethereum block time estimated to " + result + "ms");
            return result;
        }

        private TransactionReceipt waitEthTransactionToConfirm(TransactionReceipt transferReceipt, int requiredConfirmations) throws InterruptedException, IOException {
            Thread.sleep(getEthBlockDuration() * (requiredConfirmations + 1));

            EthBlock ethBlockResult;
            int confirmationRetries = 10;
            while (--confirmationRetries >= 0) {
                ethBlockResult = web3j.ethGetBlockByNumber(
                        DefaultBlockParameterName.LATEST, false).send();
                if (ethBlockResult.hasError()) {
                    throw new RuntimeException("Get latest block failed " + ethBlockResult.getError());
                }
                int currentConfirmations = ethBlockResult.getBlock().getNumber().subtract(transferReceipt.getBlockNumber()).intValueExact();
                if (currentConfirmations >= requiredConfirmations) {
                    break;
                }
                Logger.logErrorMessage("MB-ERC20 | waitEthTransactionToConfirm | Not enough Ethereum confirmations " + currentConfirmations);
                Thread.sleep((requiredConfirmations - currentConfirmations + 1) * getEthBlockDuration());
            }
            return web3j.ethGetTransactionReceipt(transferReceipt.getTransactionHash()).send().getTransactionReceipt().orElse(null);
        }

        private boolean waitArdorTransactionToConfirm(String fullHash, int expirationTime) throws InterruptedException {
            int requiredConfirmations = params.ardorConfirmations();
            int confirmationRetries = 30;
            while (--confirmationRetries >= 0) {
                JO result = GetTransactionCall.create(ChildChain.IGNIS.getId()).fullHash(fullHash).call();
                if (result.containsKey("confirmations")) {
                    int confirmations = result.getInt("confirmations");
                    if (confirmations >= requiredConfirmations) {
                        return true;
                    } else {
                        Thread.sleep((requiredConfirmations - confirmations + 1) * ARDOR_BLOCK_TIME * 1000L);
                    }
                } else {
                    int expirationTimeMinusBlockDeadline = expirationTime - DEFAULT_CHILD_BLOCK_DEADLINE;
                    int now = Nxt.getEpochTime();
                    Logger.logInfoMessage("MB-ERC20 | waitArdorTransactionToConfirm | Transaction " + fullHash + " not yet accepted expiring=" + (now > expirationTimeMinusBlockDeadline));
                    if (now > expirationTimeMinusBlockDeadline) {
                        //chances that the transaction will be bundled are low. Retrying
                        return false;
                    }
                    Thread.sleep(UNCONFIRMED_TX_RETRY_MILLIS);
                }
            }
            return false;
        }
    }

    public enum WrapState {
        CHECK_SEND_TO_EBA,
        FUND_DEPOSIT_ACCOUNT,
        SEND_TO_EBA,
        WAIT_ARRIVAL_CONFIRMATION,
        TRANSFER_ASSET
    }

    public static abstract class Task implements Runnable {
        public static final int IO_EXCEPTION_RETIRES = 5;
        final PegContext context;

        Task(PegContext context) {
            this.context = context;
        }

        /**
         * Execute the task logic
         *
         * @return True if the execution completed, false if this method should be called again
         */
        abstract boolean execute() throws Exception;

        abstract void onFailure(String error);

        void scheduleExecution() {
            context.executor.submit(this);
        }

        @Override
        public void run() {
            int retries = IO_EXCEPTION_RETIRES;
            Throwable throwable = null;
            while (retries > 0) {
                try {
                    if (execute()) {
                        return;
                    } else {
                        retries = IO_EXCEPTION_RETIRES;
                    }
                } catch (Throwable t) {
                    throwable = t;
                    String message = "Task " + this + " failed";
                    if (t instanceof IOException) {
                        retries--;
                        message += ". Retries left: " + retries;
                    } else {
                        retries = 0;
                    }
                    Logger.logErrorMessage(message, t);
                }
            }
            onFailure("" + throwable);
        }
    }

    public static class mbWrapTask extends Task {
        private final ContractRunnerConfig contractRunnerConfig;
        private final String taskId;
        private final String tokenAddress;
        private final BigInteger amount;
        private final BigInteger depositEthHeight;
        private final Credentials depositAccount;
        private final byte[] recipientPublicKey;
        private WrapState state;
        private BigInteger gasPrice;
        private BigInteger estimatedGas;
        private TransactionReceipt receipt;

        public mbWrapTask(PegContext pegContext, ContractRunnerConfig config, String id,
                          String tokenAddress, BigInteger amount, BigInteger depositEthHeight,
                          Credentials depositAccount, String recipientPublicKey) {
            super(pegContext);
            this.contractRunnerConfig = config;
            this.taskId = id;
            this.tokenAddress = tokenAddress;
            this.amount = amount;
            this.depositEthHeight = depositEthHeight;
            this.depositAccount = depositAccount;
            this.recipientPublicKey = Convert.parseHexString(recipientPublicKey);
            this.state = WrapState.CHECK_SEND_TO_EBA;
        }

        public void setState(WrapState state) {
            Logger.logInfoMessage("State " + this.state + ">" + state + " " + taskId);
            this.state = state;
        }

        @Override
        public boolean execute() throws Exception {
            switch (state) {
                case CHECK_SEND_TO_EBA:
                    gasPrice = context.getEthGasPrice();
                    Logger.logInfoMessage("MB-ERC20 | mbWrapTask | CHECK_SEND_TO_EBA | address: " + depositAccount.getAddress() + " | EBA Address: " + context.ethBlockedAccount.getAddress() + " | ETH Contract: " + context.params.contractAddress() + " | Gas price: " + gasPrice);
                    setState(WrapState.FUND_DEPOSIT_ACCOUNT);
                    scheduleExecution();
                    break;

                case FUND_DEPOSIT_ACCOUNT:
                    Function function = Utils.createTransferFunction(context.ethBlockedAccount.getAddress(), this.amount);
                    String data = FunctionEncoder.encode(function);
                    org.web3j.protocol.core.methods.request.Transaction transaction = new org.web3j.protocol.core.methods.request.Transaction(
                            depositAccount.getAddress(),
                            null, null, null,
                            context.ethBlockedAccount.getAddress(), BigInteger.ZERO, data);

                    estimatedGas = (context.web3j.ethEstimateGas(transaction).send().getAmountUsed()).multiply(BigInteger.valueOf(3));
                    BigInteger estimatedTransferTransactionPrice = gasPrice.multiply(estimatedGas);

                    TransactionReceipt receipt = new Transfer(context.web3j, context.ebaTransactionManager)
                            .sendFunds(depositAccount.getAddress(), new BigDecimal(estimatedTransferTransactionPrice),
                                    org.web3j.utils.Convert.Unit.WEI).send();

                    context.ebaTransactionManager.setCallbacks(receipt, (tr, p) -> {
                        logTransactionReceipt("MB-ERC20 | mbWrapTask | FUND_DEPOSIT_ACCOUNT | Deposit account funding " + depositAccount.getAddress(), tr.getTransactionHash());
                        setState(WrapState.SEND_TO_EBA);
                        scheduleExecution();
                    }, this::onFailure);
                    break;

                case SEND_TO_EBA:
                    StaticGasProvider depositContractGasProvider = new StaticGasProvider(gasPrice, estimatedGas);

                    RetryingRawTransactionManager depositAccountTransactionManager =
                            context.createTransactionManager(context.params, this.depositAccount, true);

                    IERC20 contractByDepositAccount = IERC20.load(context.params.contractAddress(),
                            context.web3j,
                            depositAccountTransactionManager,
                            depositContractGasProvider);

                    Logger.logInfoMessage("MB-ERC20 | mbWrapTask | SEND_TO_EBA | From: " + depositAccount.getAddress() + " | To " + context.ethBlockedAccount.getAddress() + " | wETH Amount: " + this.amount);
                    TransactionReceipt emptyReceipt = contractByDepositAccount.transfer(context.ethBlockedAccount.getAddress(), this.amount).send();

                    depositAccountTransactionManager.setCallbacks(emptyReceipt, (tr, r) -> {
                        this.receipt = tr;
                        logTransactionReceipt("MB-ERC20 | mbWrapTask | SEND_TO_EBA | Funded by " + depositAccount.getAddress(), tr.getTransactionHash());
                        setState(WrapState.WAIT_ARRIVAL_CONFIRMATION);
                        scheduleExecution();
                    }, error -> {
                        if (error != null && error.contains(ErrorMsg.INSUFFICIENT_FUNDS)) {
                            gasPrice = context.getNewGasPrice(gasPrice);
                            Logger.logInfoMessage("MB-ERC20 | mbWrapTask | INSUFFICIENT_FUNDS | NEW GAS: " + gasPrice);
                            setState(WrapState.FUND_DEPOSIT_ACCOUNT);
                            scheduleExecution();
                        } else {
                            Logger.logInfoMessage("MB-ERC20 | mbWrapTask | ONFAILURE");
                            onFailure(error);
                        }
                    });
                    break;

                case WAIT_ARRIVAL_CONFIRMATION:
                    //TODO make async
                    TransactionReceipt approvalReceipt = context.waitEthTransactionToConfirm(this.receipt, context.params.ethereumConfirmations());
                    if (approvalReceipt != null) {
                        logTransactionReceipt("MB-ERC20 | mbWrapTask | WAIT_ARRIVAL_CONFIRMATION | wETH confirmed in EBA ", approvalReceipt.getTransactionHash());
                        setState(WrapState.TRANSFER_ASSET);
                        scheduleExecution();
                    } else {
                        throw new RuntimeException("B-ERC20 | mbWrapTask | WAIT_ARRIVAL_CONFIRMATION | SEND FAILED TO EBA.");
                    }
                    break;

                case TRANSFER_ASSET:
                    Logger.logWarningMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET");

                    long feeRate = contractRunnerConfig.getCurrentFeeRateNQTPerFXT(ChildChain.IGNIS.getId());
                    long feeIncrease = Math.multiplyExact(feeRate,
                            Integer.parseInt(context.params.ardorInitialFeeOverpayPercent())) / 100;
                    Logger.logInfoMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | feeRate=" + feeRate + "+ (INCREASE: " + feeIncrease + ")");
                    feeRate = Math.addExact(feeRate, feeIncrease);

                    BigDecimal amountInEther = org.web3j.utils.Convert.fromWei(amount.toString(), org.web3j.utils.Convert.Unit.ETHER);
                    Logger.logInfoMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | Value in ETHER: " + amountInEther);

                    BigInteger etherInQNT = amountInEther.multiply(QNT_FACTOR).toBigInteger();
                    Logger.logInfoMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | moreTest: " + etherInQNT);

                    TransferAssetCall transferAssetCall = TransferAssetCall.create(ChildChain.IGNIS.getId())
                            .privateKey(contractRunnerConfig.getPrivateKey())
                            .recipientPublicKey(recipientPublicKey)
                            .recipient(Account.getId(recipientPublicKey))
                            .asset(Long.parseUnsignedLong(context.params.assetId()))
                            .quantityQNT(etherInQNT.longValueExact())
                            .feeRateNQTPerFXT(feeRate)
                            .compressMessageToEncrypt("false")
                            .messageToEncryptIsText(false)
                            .encryptedMessageIsPrunable(true);

                    if (contractRunnerConfig.getDefaultDeadline() > 0)
                        transferAssetCall.deadline(contractRunnerConfig.getDefaultDeadline());

                    while (true) {
                        Logger.logDebugMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | Asset transfer...");
                        JO result = transferAssetCall.build().invoke();
                        if (result.getString("fullHash") != null) {
                            String fullHash = result.getString("fullHash");
                            Logger.logInfoMessage("MMB-ERC20 | mbWrapTask | TRANSFER_ASSET | FullHash: " + fullHash);

                            int expirationTime = getExpirationTime(result.getJo("transactionJSON"));
                            if (context.waitArdorTransactionToConfirm(fullHash, expirationTime)) break;

                            long increase = Math.multiplyExact(feeRate, context.params.ardorRetryFeeOverpayPercent()) / 100;
                            Logger.logInfoMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | Increasing Ardor transaction fee rate from " + feeRate + " with " + increase);
                            feeRate = Math.addExact(feeRate, increase);
                            transferAssetCall.feeRateNQTPerFXT(feeRate);

                            while (Nxt.getEpochTime() < expirationTime + Constants.MAX_TIMEDRIFT)
                                Thread.sleep(500);

                            //check again if the transaction was confirmed since waitArdorTransactionToConfirm
                            // assumes the default DEFAULT_CHILD_BLOCK_DEADLINE, but some bundler may use other value
                            if (context.waitArdorTransactionToConfirm(fullHash, expirationTime))
                                break;
                        } else {
                            throw new RuntimeException("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | Send unwrapped tokens failed: " + result.getString("errorDescription"));
                        }
                    }
                    Logger.logInfoMessage("MB-ERC20 | mbWrapTask | TRANSFER_ASSET | Task " + taskId + " completed successfully");
                    context.wrapTasks.remove(taskId);
                    break;
                default:
                    throw new IllegalStateException("MB-ERC20 | mbWrapTask | Unexpected value: " + state);
            }
            return true;
        }

        @Override
        void onFailure(String error) {
            Logger.logInfoMessage("MB-ERC20 | mbWrapTask | onFailure | Task " + taskId + " failed with error " + error);
            context.wrapTasks.remove(taskId);
        }
    }

    static int getExpirationTime(JO transactionJson) {
        return transactionJson.getInt("timestamp") + transactionJson.getInt("deadline") * 60;
    }

}