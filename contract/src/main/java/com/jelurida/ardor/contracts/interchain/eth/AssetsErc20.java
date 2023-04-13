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

import com.jelurida.web3j.generated.BRIDGE_ERC20;
import com.jelurida.web3j.generated.IERC20;
//import com.jelurida.web3j.generated.IERC20Ardor;
import com.jelurida.web3j.utils.TransactionalContract;
import com.jelurida.web3j.utils.Utils;
import com.jelurida.web3j.utils.protocol.AlchemyHttpService;
import com.jelurida.web3j.utils.txman.RetryFeeProvider;
import com.jelurida.web3j.utils.txman.RetryingRawTransactionManager;
import nxt.Constants;
import nxt.Nxt;
import nxt.account.Account;
import nxt.addons.AbstractContract;
import nxt.addons.AbstractContractContext;
import nxt.addons.BlockContext;
import nxt.addons.ContractParametersProvider;
import nxt.addons.ContractRunnerConfig;
import nxt.addons.ContractRunnerParameter;
import nxt.addons.ContractSetupParameter;
import nxt.addons.InitializationContext;
import nxt.addons.JA;
import nxt.addons.JO;
import nxt.addons.RequestContext;
import nxt.addons.ShutdownContext;
import nxt.ae.AssetExchangeTransactionType;
import nxt.blockchain.ChildChain;
import nxt.crypto.Crypto;
import nxt.crypto.EncryptedData;
import nxt.http.callers.GetAssetCall;
import nxt.http.callers.GetExecutedTransactionsCall;
import nxt.http.callers.GetTransactionCall;
import nxt.http.callers.ReadMessageCall;
import nxt.http.callers.TransferAssetCall;
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
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthLog;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.Transaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.Transfer;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static nxt.util.JSON.jsonArrayCollector;

public class AssetsErc20 extends AbstractContract<Object, Object> {

    public static final int DEFAULT_CHILD_BLOCK_DEADLINE = 10 * 60;
    public static final int UNCONFIRMED_TX_RETRY_MILLIS = Constants.isTestnet && Constants.isAutomatedTest ? 5000 : 15000;
    public static final int ARDOR_BLOCK_TIME = Constants.isTestnet ? (Constants.isAutomatedTest ? 1 : Constants.BLOCK_TIME / Constants.TESTNET_ACCELERATION) : Constants.BLOCK_TIME;
    public static final String CONTRACT_ADDRESS_MISSING_ERROR = "contractAddress missing - Please config in contractRunner";
    public static final BigInteger MAX_UNSIGNED_LOG_VALUE = BigInteger.valueOf(2).pow(64).subtract(BigInteger.ONE);

    public static final long ETH_BLOCK_TIME_ESTIMATION_EXPIRATION = 720 * 60;
    public static final BigInteger ETH_BLOCK_TIME_ESTIMATION_BLOCK_COUNT = BigInteger.valueOf(1000);
    public static final int DEFAULT_ETH_BLOCK_TIME = 2000;
    public static final long ETH_GAS_PRICE_ESTIMATION_EXPIRATION = 60 * 60;
    private final PegContext pegContext = new PegContext();

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

        /**
         * Confirmations to wait before processing the wrapping of Ardor assets with ERC1155 tokens
         *
         * @return Number of blocks
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default int ardorConfirmations() {
            return 30;
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

        /**
         * Confirmations to wait before processing the unwrapping of ERC1155 tokens and releasing the
         * locked Ardor assets
         *
         * @return Number of blocks
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default int ethereumConfirmations() {
            return 30;
        }

        /**
         * Seconds before we give up waiting for the ethereum transaction to be accepted in a block and retry with
         * higher fee
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

        /**
         * Secret used to generate the credentials of the Ethereum account which holds the locked ERC1155
         * tokens
         * @return Secret string. Use at least 160 bits of entropy
         */
        @ContractRunnerParameter
        String ethereumBlockedAccountSecret();

        /**
         * A secret concatenated to the Ardor account public key in order to deterministically get the
         * credentials of an Ethereum deposit account dedicated to the owner of the public key
         * @return Secret string. Use at least 160 bits of entropy
         */
        @ContractRunnerParameter
        String ethereumDepositAccountsSecret();

        /**
         * The contract address which will be managing the tokens on ethereum side. Must implement
         * @return Ethereum address - string in format '0x' followed by 20 bytes in hex format (40 characters)
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        String contractAddress();

        /**
         * Mapping between ardor asset IDs and the ERC1155 token IDs. The JSON keys must contain
         * asset IDs as unsigned integer strings. The corresponding values must contain ERC1155
         * token IDs as unsigned integer string, or a string with format '0x' followed by up to
         * 64 hex chars (32 bytes in hex format)
         *
         * This parameter is ignited if {@link #autoMintErc1155()} is true
         *
         * @return Mapping as JSON object
         */
        @ContractRunnerParameter
        @ContractSetupParameter
        default JO assetIdToErc20IdMap() {
            return null;
        }
    }

    @Override
    public void init(InitializationContext context) {
        lastUnwrapHeight = context.getBlockchainHeight();
        threadPool = Executors.newCachedThreadPool();
        Parameters params = context.getParams(Parameters.class);
        pegContext.init(params, threadPool);
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

        String command = getParameter(context, requestParams,"command");
        if (command == null)
            return context.generateErrorResponse(10001, "Please specify a 'command' parameter");

        if (pegContext.initializationError != null)
            return context.generateErrorResponse(10004, "Peg initialization error " + pegContext.initializationError);

        if ("getPegAddresses".equals(command)) {
            response.put("ethereumBlockedAccount", pegContext.ethBlockedAccount.getAddress());
            response.put("ardorBlockedAccount", context.getAccountRs());
        } else if ("mbGetWrapDepositAddress".equals(command)) {
            String ardorRecipientPublicKey = getArdorRecipientPublicKeyParameter(context, requestParams);
            if (ardorRecipientPublicKey == null)
                return context.getResponse();
            response.put("depositAddress", getUnwrapDepositAccount(params, ardorRecipientPublicKey).getAddress());
        } else if ("mbProcessWrapsForAccount".equals(command)) {
            String ardorRecipientPublicKey = getArdorRecipientPublicKeyParameter(context, requestParams);
            if (ardorRecipientPublicKey == null) {
                return context.getResponse();
            }
            return mbProcessWrapsForAccount(context, ardorRecipientPublicKey);
        } else if ("mbProcessUnwrapsAtHeight".equals(command)) {
            String heightStr = getParameter(context, requestParams, "height");
            if (heightStr == null) {
                return context.generateErrorResponse(10001, "Please specify a 'height' parameter");
            }
            return mbProcessUnwrapsAtHeight(context, Integer.parseInt(heightStr));
        } else if ("mbGetUnwrappingLog".equals(command)) {
            response.put("log", wrappingLog.stream().collect(jsonArrayCollector()));
        } else if ("secretToEthPrivateKey".equals(command)) {
            String secret = getParameter(context, requestParams, "secret");
            if (secret == null) {
                return context.generateErrorResponse(10001, "Please specify a 'secret' parameter");
            }
            Credentials credentials = getCredentialsFromSecret(secret);
            response.put("address", credentials.getAddress());
            response.put("privateKeyNumeric", credentials.getEcKeyPair().getPrivateKey().toString());
            response.put("privateKeyHex", Numeric.encodeQuantity(credentials.getEcKeyPair().getPrivateKey()));
        }
        return response;
    }

    @Override
    public JO processBlock(BlockContext context) {
        if (pegContext.initializationError != null) {
            return context.generateErrorResponse(10004, "Peg not initialized " + pegContext.initializationError);
        }
        Parameters params = context.getParams(Parameters.class);
        BlockResponse block = context.getBlock();
        if (!Constants.isAutomatedTest && block.getTimestamp() < Nxt.getEpochTime() - ARDOR_BLOCK_TIME * params.ardorConfirmations()) {
            return context.generateInfoResponse("Block too old - " + new Date(Convert.fromEpochTime(block.getTimestamp())));
        }
        int height = context.getHeight();
        if (height > lastUnwrapHeight) {
            lastUnwrapHeight = height;
            return mbProcessUnwrapsAtHeight(context, height - params.ardorConfirmations());
        } else {
            return context.generateInfoResponse("Height already processed or before contract initialization: " + height);
        }
    }

    private JO mbProcessUnwrapsAtHeight(AbstractContractContext context, int height) {
        if (height <= 0 || height > context.getBlockchainHeight())
            return context.generateErrorResponse(10003, "Invalid height " + height);

        if (pegContext.initializationError != null)
            return context.generateErrorResponse(10004, "Peg initialization error " + pegContext.initializationError);

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

            if (Numeric.cleanHexPrefix(recipientAddress).length() > Address.MAX_BYTE_LENGTH * 2
                    || !recipientAddress.equalsIgnoreCase(Keys.toChecksumAddress(recipientAddress))) {
                result.put("error", "Invalid address in transaction message: " + recipientAddress);
                return result;
            }
            JO attachment = transaction.getJo("attachment");
            String assetIdStr = attachment.getString("asset");
            long assetId = Long.parseUnsignedLong(assetIdStr);
            String tokenAddress = pegContext.assetIdToEthTokenAddress(assetId);
            if (tokenAddress != null) {
                //check the asset here too because during initialization the blockchain might not have been up-to date
                if (!pegContext.validateAsset(assetId, true)) {
                    throw new RuntimeException("Found invalid asset: " + pegContext.initializationError);
                }
                BigInteger amountToTransfer = new BigInteger((String) attachment.get("quantityQNT"));

                //check in the last ethLogsBlockRange * ethLogsIterations blocks whether the transaction was already processed.
                // This is enough since the automatic wrapping is executed only for the latest blocks
                BigInteger height = pegContext.web3j.ethBlockNumber().send().getBlockNumber();
                List<Log> logs = getTransfersLogs(pegContext, height,
                        pegContext.ethBlockedAccount.getAddress(),
                        recipientAddress, null);

                Log logFromExistingWrap = logs.stream().filter(log ->
                        mbIsExistingWrappingLog(context, log, tokenAddress, amountToTransfer, fullHash)).findAny().orElse(null);

                if (logFromExistingWrap == null) {
                    RemoteFunctionCall<TransactionReceipt> call = pegContext.getEthContractForTransaction(BRIDGE_ERC20.class)
                                .safeTransferFrom(pegContext.params.contractAddress(),
                                        amountToTransfer, recipientAddress);
                    call.sendAsync().thenAccept(emptyReceipt -> {
                        pegContext.ebaTransactionManager.setCallbacks(emptyReceipt, (tr, p) -> {
                            logTransactionReceipt("Wrapping complete ", tr.getTransactionHash());
                            result.put("success", tr.getTransactionHash());
                        }, (error) -> result.put("error", error));
                    }).exceptionally(e -> {
                        Logger.logErrorMessage("Wrapping", e);
                        result.put("error", "Transfer: " + e.getMessage());
                        return null;
                    });
                } else {
                    result.put("error", "Transfer already processed " + logFromExistingWrap);
                }
            } else {
                result.put("error", "Transfers unknown asset " + assetIdStr);
            }
        } catch (Exception e) {
            context.logErrorMessage(e);
            result.put("error", "Exception " + e.getMessage());
        }
        return result;
    }

    private boolean mbIsExistingWrappingLog(AbstractContractContext context, Log log, String tokenAddress,
                                          BigInteger amount, String wrapTriggeringFullHash) {
        if (!isTransferTokenAndAmountEqual(log, tokenAddress, amount)) {
            return false;
        }
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

    private static boolean isTransferTokenAndAmountEqual(Log log, String tokenAddress, BigInteger amount) {
        EventValues eventValues = Contract.staticExtractEventParameters(IERC20.TRANSFER_EVENT, log);
        return tokenAddress.equals(Utils.getEventValueBigInteger(eventValues, 0))
                && amount.equals(Utils.getEventValueBigInteger(eventValues, 1));
    }

    private static Transaction getEthTransactionByHash(Web3j web3j, String transactionHash) {
        EthTransaction ethTransactionOrError;
        try {
            ethTransactionOrError = web3j.ethGetTransactionByHash(transactionHash).send();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (ethTransactionOrError.hasError()) {
            throw new RuntimeException("ethGetTransactionByHash failed: " + ethTransactionOrError.getError());
        }
        return ethTransactionOrError.getTransaction().orElseThrow(() -> new RuntimeException("ethGetTransactionByHash returned null"));
    }

    private JO mbProcessWrapsForAccount(RequestContext context, String recipientPublicKey) {
        try {
            Logger.logInfoMessage("MB-Wrap: mbProcessWrapsForAccount");
            Parameters params = context.getParams(Parameters.class);

            Credentials depositAccount = getUnwrapDepositAccount(params, recipientPublicKey);
            BigInteger height = pegContext.web3j.ethBlockNumber().send().getBlockNumber();
            List<Log> logs = getTransfersLogs(pegContext, height, null, depositAccount.getAddress(), null);
            AtomicReference<Set<mbWrapTaskId>> completedWrapIds = new AtomicReference<>();
            JO response = new JO();
            logs.forEach(log -> {
                        EventValues eventValues = Contract.staticExtractEventParameters(IERC20.TRANSFER_EVENT, log);
                        String tokenAddress = log.getAddress();
                        if (isKnownWrappingToken(tokenAddress)) {
                            Logger.logInfoMessage("MB-Wrap: isKnownWrappingToken");
                            //check the asset here too because during initialization the blockchain might not have been up-to date
                            if (!pegContext.validateAsset(pegContext.ethTokenAddressToAssetId(tokenAddress), true)) {
                                throw new RuntimeException("Found invalid asset: " + pegContext.initializationError);
                            }
                            mbWrapTaskId id = new mbWrapTaskId(log);
                            if (!pegContext.wrapTasks.containsKey(id)) {
                                Logger.logInfoMessage("MB-Wrap: !pegContext.wrapTasks.containsKey(id)");
                                completedWrapIds.compareAndSet(null, getCompletedWrapIds(context, recipientPublicKey));
                                if (!completedWrapIds.get().contains(id)) {
                                    Logger.logInfoMessage("MB-Wrap: !completedWrapIds.get().contains(id)");
                                    BigInteger amount = Utils.getEventValueBigInteger(eventValues, 0);
                                    mbWrapTask newTask = new mbWrapTask(pegContext, context.getConfig(), id,
                                            tokenAddress, amount, log.getBlockNumber(),
                                            depositAccount, recipientPublicKey);
                                    if (pegContext.wrapTasks.putIfAbsent(id, newTask) == null) {
                                        Logger.logInfoMessage("Unwrap task " + id + " started by transaction " + log.getTransactionHash());
                                        newTask.scheduleExecution();
                                        incrementResponseCounter(response, "starts");
                                    } else {
                                        incrementResponseCounter(response, "skippedAlreadyPending");
                                    }
                                } else {
                                    incrementResponseCounter(response, "skippedCompleted");
                                }
                            } else {
                                incrementResponseCounter(response, "skippedAlreadyPending");
                            }
                        } else {
                            incrementResponseCounter(response, "unknownTokens");
                        }
                    });
            return context.generateResponse(response);

        } catch (Exception e) {
            context.logErrorMessage(e);
            return context.generateErrorResponse(10500, "" + e);
        }
    }

    private boolean isKnownWrappingToken(String tokenAddress) {
        return pegContext.erc20ToArdor.containsKey(tokenAddress);
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
                    "0xfbbd91eaedd6773dd1d976e75c3de55bb342fdd0")
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
    private Set<mbWrapTaskId> getCompletedWrapIds(RequestContext context, String recipientPublicKey) {
        Set<mbWrapTaskId> result = new HashSet<>();
        byte[] recipientPublicKeyBytes = Convert.parseHexString(recipientPublicKey);
        long unwrapRecipient = Account.getId(recipientPublicKeyBytes);
        JA transactions = GetExecutedTransactionsCall.create(ChildChain.IGNIS.getId())
                .sender(context.getAccountRs())
                .recipient(unwrapRecipient)
                .type(AssetExchangeTransactionType.ASSET_TRANSFER.getType())
                .subtype(AssetExchangeTransactionType.ASSET_TRANSFER.getSubtype())
                .callNoError()
                .getArray("transactions");
        transactions.objects().forEach(t -> {
            JO attachment = t.getJo("attachment");
            if (attachment != null) {
                JO encryptedMessage = attachment.getJo("encryptedMessage");
                if (encryptedMessage != null && Boolean.FALSE.equals(encryptedMessage.get("isText"))) {
                    EncryptedData encryptedData = new EncryptedData(
                            Convert.parseHexString((String)encryptedMessage.get("data")),
                            Convert.parseHexString((String)encryptedMessage.get("nonce")));
                    result.add(new mbWrapTaskId(context.getConfig().decryptFrom(recipientPublicKeyBytes, encryptedData, false)));
                }
            }
        });
        return result;
    }

    @NotNull
    private Credentials getUnwrapDepositAccount(Parameters params, String publicKey) {
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
        private final Map<String, Long> erc20ToArdor = new HashMap<>();
        private final Map<Long, String> ardorToErc20 = new HashMap<>();
        private final Map<Long, JO> assetInfo = new HashMap<>();
        private Parameters params;
        private Web3j web3j;
        private ExecutorService executor;
        private TransactionalContract ethContract;
        private long ethBlockTimeEstimation = DEFAULT_ETH_BLOCK_TIME;
        private long lastEthBlockTimeEstimationTime = 0;
        private BigInteger ethGasPrice = null;
        private long lastEthGasPriceEstimationTime = 0;
        private RetryingRawTransactionManager ebaTransactionManager;
        private final ConcurrentHashMap<mbWrapTaskId, mbWrapTask> wrapTasks = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, ApprovalTask> approvalTasks = new ConcurrentHashMap<>();

        public PegContext() {}

        public void init(Parameters params, ExecutorService executor) {
            this.executor = executor;
            initializationError = null;
            if (Convert.emptyToNull(params.ethereumBlockedAccountSecret()) == null) {
                initializationError = "ethereumBlockedAccountSecret missing | Test";
                return;
            }
            if (Convert.emptyToNull(params.ethereumDepositAccountsSecret()) == null) {
                initializationError = "ethereumDepositAccountsSecret missing";
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, String> jo = params.assetIdToErc20IdMap();
            if (jo == null) {
                initializationError = "Need to provide assetIdToErc20IdMap";
            } else {
                jo.forEach((assetIdString, tokenIdString) -> {
                    Long assetId = Long.parseUnsignedLong(assetIdString);
                    validateAsset(assetId, false);
                    ardorToErc20.put(assetId, tokenIdString);
                    erc20ToArdor.put(tokenIdString, assetId);
                });
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
                return;
            }

            ethContract = new TransactionalContract("0xfbbd91eaedd6773dd1d976e75c3de55bb342fdd0", web3j,
                    ebaTransactionManager, new DefaultGasProvider());

            if(ethContract == null) {
                initializationError = "Cannot set ethContact, is null.";
                return;
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

        public Long ethTokenAddressToAssetId(String tokenAddress) {
            return erc20ToArdor.get(tokenAddress);
        }

        @Nullable
        private String assetIdToEthTokenAddress(long assetId) {
            return ardorToErc20.get(assetId);
        }

        public synchronized long getEthBlockDuration() throws IOException {
            long now = System.currentTimeMillis();
            if (now - lastEthBlockTimeEstimationTime > ETH_BLOCK_TIME_ESTIMATION_EXPIRATION * 1000) {
                ethBlockTimeEstimation = estimateEthBlockTime();
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
                Logger.logInfoMessage("ethGasPrice=" + gasPrice + "+(" + initialOverpay + ")=" + ethGasPrice);
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
                Logger.logInfoMessage("Increasing gas price: " + failedTransactionGasPrice + "+" + gasPriceIncrease +
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
                Logger.logErrorMessage("Get latest block failed " + ethBlockResult.getError());
                return DEFAULT_ETH_BLOCK_TIME;
            }
            EthBlock.Block latest = ethBlockResult.getBlock();
            long now = Utils.timestampToMillis(latest.getTimestamp());
            BigInteger currentHeight = latest.getNumber();
            BigInteger oldHeight = currentHeight.subtract(ETH_BLOCK_TIME_ESTIMATION_BLOCK_COUNT);

            ethBlockResult = web3j.ethGetBlockByNumber(
                    DefaultBlockParameter.valueOf(oldHeight), false).send();

            if (ethBlockResult.hasError()) {
                Logger.logErrorMessage("Get block " + oldHeight
                        +  " failed " + ethBlockResult.getError());
                return DEFAULT_ETH_BLOCK_TIME;
            }

            long result = (now - Utils.timestampToMillis(ethBlockResult.getBlock().getTimestamp())) / ETH_BLOCK_TIME_ESTIMATION_BLOCK_COUNT.longValueExact();
            Logger.logInfoMessage("Ethereum block time estimated to " + result + "ms");
            return result;
        }

        public void ensureAccountApprovesEba(mbWrapTask wrapTask) {
            ApprovalTask newTask = new ApprovalTask(wrapTask, this);
            ApprovalTask oldTask = approvalTasks.putIfAbsent(newTask.getAccount().getAddress(), newTask);
            if (oldTask == null) {
                newTask.scheduleExecution();
            } else {
                oldTask.waitingTasks.add(wrapTask);
            }
        }

        private TransactionReceipt waitEthTransactionToConfirm(TransactionReceipt transferReceipt, int requiredConfirmations) throws InterruptedException, IOException {
            Thread.sleep(getEthBlockDuration() * (requiredConfirmations + 1));

            EthBlock ethBlockResult;
            int confirmationRetries = 10;
            while(--confirmationRetries >= 0) {
                ethBlockResult = web3j.ethGetBlockByNumber(
                        DefaultBlockParameterName.LATEST, false).send();
                if (ethBlockResult.hasError()) {
                    throw new RuntimeException("Get latest block failed " + ethBlockResult.getError());
                }
                int currentConfirmations = ethBlockResult.getBlock().getNumber().subtract(transferReceipt.getBlockNumber()).intValueExact();
                if (currentConfirmations >= requiredConfirmations) {
                    break;
                }
                Logger.logErrorMessage("Not enough Ethereum confirmations " + currentConfirmations);
                Thread.sleep((requiredConfirmations - currentConfirmations + 1) * getEthBlockDuration());
            }
            return web3j.ethGetTransactionReceipt(transferReceipt.getTransactionHash()).send().getTransactionReceipt().orElse(null);
        }

        public IERC20 getEthContractReadOnly() {
            return ethContract.getReadOnly(IERC20.class);
        }

        public <T extends Contract> T getEthContractForTransaction(Class<T> contractClass) throws IOException {
            return ethContract.getForTransaction(contractClass, ethBlockedAccount.getAddress(), getEthGasPrice());
        }

        private boolean waitArdorTransactionToConfirm(String fullHash, int expirationTime) throws InterruptedException {
            int requiredConfirmations = params.ardorConfirmations();
            int confirmationRetries = 30;
            while(--confirmationRetries >= 0) {
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
                    Logger.logInfoMessage("Transaction " + fullHash + " not yet accepted expiring=" + (now > expirationTimeMinusBlockDeadline));
                    if (now > expirationTimeMinusBlockDeadline) {
                        //chances that the transaction will be bundled are low. Retrying
                        return false;
                    }
                    Thread.sleep(UNCONFIRMED_TX_RETRY_MILLIS);
                }
            }
            return false;
        }
    /*
        public Set<Long> getSupportedAssets() {
            return Collections.unmodifiableSet(ardorToErc20.keySet());
        }

     */
    }

    /*
    static long convertEthIdToArdorId(BigInteger ethId) {
        if (ethId.compareTo(MAX_UNSIGNED_LOG_VALUE) > 0) {
            return 0;
        }
        return Long.parseUnsignedLong(ethId.toString());
    }
    */

    static BigInteger convertArdorIdToEthId(long ardorId) {
        return new BigInteger(Long.toUnsignedString(ardorId), 10);
    }

    public enum WrapState {
        ENSURE_ACCOUNT_WITHDRAWER_ROLE,
        FUND_DEPOSIT_ACCOUNT,
        WAIT_APPROVAL_CONFIRMATION,
        CHECK_EXISTING_BURN,
        WAIT_BURN_TO_CONFIRM,
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

    public static class ApprovalTask extends Task {
        final List<mbWrapTask> waitingTasks = new CopyOnWriteArrayList<>();
        private BigInteger gasPrice;
        private BigInteger estimatedGas;
        private TransactionReceipt receipt;

        ApprovalTask(mbWrapTask startingTask, PegContext context) {
            super(context);
            waitingTasks.add(startingTask);
        }

        Credentials getAccount() {
            return waitingTasks.get(0).depositAccount;
        }

        BigInteger getAmount() {
            return waitingTasks.get(0).amount;
        }

        @Override
        public boolean execute() throws Exception {
            if (getState() == WrapState.ENSURE_ACCOUNT_WITHDRAWER_ROLE) {
                BigInteger allowance = context.getEthContractReadOnly().allowance(getAccount().getAddress(),
                        context.params.contractAddress()).send();

                if (getAmount().compareTo(allowance) == 1) {
                    gasPrice = context.getEthGasPrice();
                    setState(WrapState.FUND_DEPOSIT_ACCOUNT);
                    return false;
                } else {
                    onComplete();
                }
            } else if (getState() == WrapState.FUND_DEPOSIT_ACCOUNT) {
                Function function = Utils.createSetApprovalForAllFunction(context.params.contractAddress(), true);
                String data = FunctionEncoder.encode(function);
                org.web3j.protocol.core.methods.request.Transaction transaction = new org.web3j.protocol.core.methods.request.Transaction(
                        getAccount().getAddress(),
                        null, null, null, context.params.contractAddress(), BigInteger.ZERO, data);
                estimatedGas = context.web3j.ethEstimateGas(transaction).send().getAmountUsed();

                BigInteger estimatedApprovalTransactionPrice = gasPrice.multiply(estimatedGas);

                TransactionReceipt receipt = new Transfer(context.web3j, context.ebaTransactionManager)
                        .sendFunds(context.params.contractAddress(), new BigDecimal(estimatedApprovalTransactionPrice),
                                org.web3j.utils.Convert.Unit.WEI).send();
                context.ebaTransactionManager.setCallbacks(receipt, (tr, p) -> {
                    logTransactionReceipt("MB-Bridge: Deposit account funding " + getAccount().getAddress(), tr.getTransactionHash());
                    setState(WrapState.WAIT_APPROVAL_CONFIRMATION);
                    scheduleExecution();
                }, this::onFailure);
            }  else if (getState() == WrapState.WAIT_APPROVAL_CONFIRMATION) {
                //TODO make async
                TransactionReceipt approvalReceipt = context.waitEthTransactionToConfirm(receipt, 1);
                if (approvalReceipt != null) {
                    logTransactionReceipt("Approval confirmed ", approvalReceipt.getTransactionHash());
                } else {
                    throw new RuntimeException("Failed to Approve EBA by " + getAccount().getAddress());
                }
                onComplete();
            }
            return true;
        }

        void onComplete() {
            setState(WrapState.CHECK_EXISTING_BURN);
            context.approvalTasks.remove(getAccount().getAddress());
            waitingTasks.forEach(Task::scheduleExecution);
        }

        @Override
        void onFailure(String error) {
            context.approvalTasks.remove(getAccount().getAddress());
            waitingTasks.forEach(task -> task.onFailure(error));
        }

        WrapState getState() {
            return waitingTasks.get(0).getState();
        }

        void setState(WrapState newState) {
            waitingTasks.forEach(t -> t.setState(newState));
        }
    }

    public static class mbWrapTaskId {
        private final String blockHash;
        private final BigInteger logIndex;

        public mbWrapTaskId(Log log) {
            this.blockHash = Convert.toHexString(Numeric.hexStringToByteArray(log.getBlockHash()));
            this.logIndex = log.getLogIndex();
        }

        public mbWrapTaskId(byte[] bytes) {
            ByteBuffer bb = ByteBuffer.wrap(bytes);

            byte[] blockHashBytes = new byte[32];
            bb.get(blockHashBytes);
            this.blockHash = Convert.toHexString(blockHashBytes);

            byte[] logIndexBytes = new byte[bb.remaining()];
            bb.get(logIndexBytes);
            this.logIndex = new BigInteger(logIndexBytes);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            mbWrapTaskId that = (mbWrapTaskId) o;
            return blockHash.equals(that.blockHash) && logIndex.equals(that.logIndex);
        }

        @Override
        public int hashCode() {
            return Objects.hash(blockHash, logIndex);
        }

        public byte[] toBytes() {
            byte[] blockHashBytes = Convert.parseHexString(blockHash);
            assert blockHashBytes.length == 32;
            byte[] indexBytes = logIndex.toByteArray();
            return ByteBuffer.allocate(blockHashBytes.length + indexBytes.length)
                    .put(blockHashBytes).put(indexBytes).array();
        }

        @Override
        public String toString() {
            return "(" + blockHash + ',' + logIndex + ")";
        }
    }

    public static class mbWrapTask extends Task {
        private final ContractRunnerConfig contractRunnerConfig;
        private final mbWrapTaskId taskId;
        private final String tokenAddress;
        private final BigInteger amount;
        private final BigInteger depositEthHeight;
        private final Credentials depositAccount;
        private final byte[] recipientPublicKey;
        private WrapState state;
        private byte[] taskIdHash;
        private TransactionReceipt burnReceipt;

        public mbWrapTask(PegContext pegContext, ContractRunnerConfig config, mbWrapTaskId id,
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
            this.state = WrapState.ENSURE_ACCOUNT_WITHDRAWER_ROLE;
        }

        public WrapState getState() {
            return state;
        }

        public void setState(WrapState state) {
            Logger.logInfoMessage("State " + this.state + ">" + state + " " + taskId);
            this.state = state;
        }

        @Override
        public boolean execute() throws Exception {
            if (state == WrapState.ENSURE_ACCOUNT_WITHDRAWER_ROLE) {
                Logger.logWarningMessage("MB-Bridge | mbWrapTask + execute | ENSURE_ACCOUNT_WITHDRAWER_ROLE");
                context.ensureAccountApprovesEba(this);
            } else if (state == WrapState.CHECK_EXISTING_BURN) {
                taskIdHash = Crypto.sha256().digest(taskId.toBytes());
                //Check if the transfer from the deposit account to EBA was already executed for this unwrap
                List<Log> logs = getTransfersLogs(context,
                        depositEthHeight.add(BigInteger.valueOf(context.params.ethLogsBlockRange() - 2)),
                        depositAccount.getAddress(),
                        context.ethBlockedAccount.getAddress(),
                        null);

                Log logFromExistingUnwrap = logs.stream().filter(log -> {
                    if (!isTransferTokenAndAmountEqual(log, tokenAddress, amount)) {
                        return false;
                    }
                    Transaction tx = getEthTransactionByHash(context.web3j, log.getTransactionHash());
                    byte[] transferData = Utils.getSafeTransferData(tx);
                    return Arrays.equals(taskIdHash, transferData);
                }).findAny().orElse(null);

                if (logFromExistingUnwrap == null) {
                    Logger.logWarningMessage("MB-Bridge: WrapState.BURN_TOKENS. logFromExistingUnwrap == null");
                } else {
                    Logger.logWarningMessage("Transfer to EBA during unwrapping was already executed " + logFromExistingUnwrap);
                    setState(WrapState.TRANSFER_ASSET);
                }
                scheduleExecution();
            } else if (state == WrapState.WAIT_BURN_TO_CONFIRM) {
                burnReceipt = context.waitEthTransactionToConfirm(burnReceipt, context.params.ethereumConfirmations());
                if (burnReceipt != null) {
                    logTransactionReceipt("Burn confirmed ", burnReceipt.getTransactionHash());
                    setState(WrapState.TRANSFER_ASSET);
                    scheduleExecution();
                } else {
                    Logger.logErrorMessage("Failed to burn ETH tokens");
                }
            } else if (state == WrapState.TRANSFER_ASSET) {
                EncryptedData encryptedData = contractRunnerConfig.encryptTo(this.recipientPublicKey, taskId.toBytes(), false);

                long feeRate = contractRunnerConfig.getCurrentFeeRateNQTPerFXT(ChildChain.IGNIS.getId());
                long feeIncrease = Math.multiplyExact(feeRate,
                        Integer.parseInt(context.params.ardorInitialFeeOverpayPercent())) / 100;
                Logger.logInfoMessage("MB-Bridge: TRANSFER_ASSET | feeRate=" + feeRate + "+(" + feeIncrease + ")");
                feeRate = Math.addExact(feeRate, feeIncrease);
                TransferAssetCall transferAssetCall = TransferAssetCall.create(ChildChain.IGNIS.getId())
                        .privateKey(contractRunnerConfig.getPrivateKey())
                        .recipientPublicKey(recipientPublicKey)
                        .recipient(Account.getId(recipientPublicKey))
                        .asset(context.ethTokenAddressToAssetId(tokenAddress))
                        .quantityQNT(amount.longValueExact())
                        .feeRateNQTPerFXT(feeRate)
                        .encryptedMessageData(encryptedData.getData())
                        .encryptedMessageNonce(encryptedData.getNonce())
                        .compressMessageToEncrypt("false")
                        .messageToEncryptIsText(false)
                        .encryptedMessageIsPrunable(true);
                if (contractRunnerConfig.getDefaultDeadline() > 0) {
                    transferAssetCall.deadline(contractRunnerConfig.getDefaultDeadline());
                }

                while (true) {
                    Logger.logDebugMessage("Asset transfer...");
                    JO result = transferAssetCall.build().invoke();
                    if (result.getString("fullHash") != null) {
                        String fullHash = result.getString("fullHash");
                        int expirationTime = getExpirationTime(result.getJo("transactionJSON"));
                        if (context.waitArdorTransactionToConfirm(fullHash, expirationTime)) {
                            break;
                        }
                        long increase = Math.multiplyExact(feeRate, context.params.ardorRetryFeeOverpayPercent()) / 100;
                        Logger.logInfoMessage("Increasing Ardor transaction fee rate from " + feeRate + " with " + increase);
                        feeRate = Math.addExact(feeRate, increase);
                        transferAssetCall.feeRateNQTPerFXT(feeRate);
                        while (Nxt.getEpochTime() < expirationTime + Constants.MAX_TIMEDRIFT) {
                            Thread.sleep(500);
                        }
                        //check again if the transaction was confirmed since waitArdorTransactionToConfirm
                        // assumes the default DEFAULT_CHILD_BLOCK_DEADLINE, but some bundler may use other value
                        if (context.waitArdorTransactionToConfirm(fullHash, expirationTime)) {
                            break;
                        }
                    } else {
                        throw new RuntimeException("Send unwrapped tokens failed: " + result.getString("errorDescription"));
                    }
                }
                Logger.logInfoMessage("Task " + taskId + " completed successfully");
                context.wrapTasks.remove(taskId);
            }
            return true;
        }

        @Override
        void onFailure(String error) {
            Logger.logInfoMessage("Task " + taskId + " failed with error " + error);
            context.wrapTasks.remove(taskId);
        }
    }

    static int getExpirationTime(JO transactionJson) {
        return transactionJson.getInt("timestamp") + transactionJson.getInt("deadline") * 60;
    }

}
