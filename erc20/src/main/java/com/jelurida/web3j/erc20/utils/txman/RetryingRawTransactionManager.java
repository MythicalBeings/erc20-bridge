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

package com.jelurida.web3j.erc20.utils.txman;

import com.jelurida.web3j.erc20.utils.ErrorMsg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.Transfer;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Async;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;

public class RetryingRawTransactionManager extends FastRawTransactionManager {

    static final Logger log = LoggerFactory.getLogger(RetryingRawTransactionManager.class);
    public static final int MAX_RETRIES = 10;
    //If a transaction failed UNSTUCK_TRIGGER_RETRIES number of times, we trigger the procedure to "un-stuck" the nonces
    // that may be preventing us from creating transactions
    public static final int UNSTUCK_TRIGGER_RETRIES = 4;
    public static final String TRANSACTION_TIMEOUT_ERROR = "transaction receipt timeout";
    private final Web3j web3j;
    private final long chainId;
    private final Credentials credentials;
    private final TransactionReceiptProcessor transactionReceiptProcessor;
    private final Map<String, PendingTransaction> pendingTransactions = new ConcurrentHashMap<>();
    private final NavigableSet<BigInteger> pendingNonces = new ConcurrentSkipListSet<>();
    private final RetryFeeProvider retryFeeProvider;

    public static RetryingRawTransactionManager create(Web3j web3j, Credentials credentials, long chainId,
                                                       int pollingAttemptsPerTxHash, long pollingFrequency,
                                                       boolean isAsyncReceiptProcessor,
                                                       RetryFeeProvider retryFeeProvider) {
        RetryCallback callback = new RetryCallback();
        TransactionReceiptProcessor transactionReceiptProcessor;
        if (isAsyncReceiptProcessor) {
            transactionReceiptProcessor = new FixedReceiptProcessor(web3j, callback, pollingAttemptsPerTxHash,
                    pollingFrequency);
        } else {
            transactionReceiptProcessor = new PollingTransactionReceiptProcessor(web3j, pollingFrequency,
                    pollingAttemptsPerTxHash);
        }

        RetryingRawTransactionManager result = new RetryingRawTransactionManager(web3j, credentials, chainId,
                transactionReceiptProcessor, retryFeeProvider);
        callback.setTransactionManager(result);
        return result;
    }

    private RetryingRawTransactionManager(Web3j web3j, Credentials credentials, long chainId,
                                          TransactionReceiptProcessor transactionReceiptProcessor,
                                          RetryFeeProvider retryFeeProvider) {
        super(web3j, credentials, chainId, transactionReceiptProcessor);
        this.web3j = web3j;
        this.chainId = chainId;
        this.credentials = credentials;
        this.transactionReceiptProcessor = transactionReceiptProcessor;
        this.retryFeeProvider = retryFeeProvider;
    }

    public void setCallbacks(TransactionReceipt emptyReceipt, AcceptanceCallback acceptanceCallback,
                             FailureCallback failureCallback) {
        PendingTransaction pendingTransaction = pendingTransactions.get(emptyReceipt.getTransactionHash());
        pendingTransaction.setCallbacks(acceptanceCallback, failureCallback);
    }

    @Override
    protected TransactionReceipt executeTransaction(BigInteger gasPrice, BigInteger gasLimit, String to, String data, BigInteger value, boolean constructor) throws IOException, TransactionException {
        try {
            TransactionReceipt transactionReceipt = super.executeTransaction(gasPrice, gasLimit, to, data, value, constructor);
            if (transactionReceiptProcessor instanceof PollingTransactionReceiptProcessor) {
                transactionComplete(transactionReceipt);
            }
            return transactionReceipt;
        } catch (TransactionException te) {
            log.error("TransactionException in executeTransaction", te);
            String hash = te.getTransactionHash().orElseThrow(() -> te);
            EthSendTransaction ethSendTransaction = retryTimedOutTransaction(hash, false);
            return transactionReceiptProcessor.waitForTransactionReceipt(ethSendTransaction.getTransactionHash());
        }
    }

    @Override
    public EthSendTransaction sendTransaction(BigInteger gasPrice, BigInteger gasLimit, String to, String data, BigInteger value, boolean constructor) throws IOException {
        BigInteger nonce = getNonce();
        Fees1559 fees1559 = calculateFees1559(gasPrice);
        RawTransaction rawTransaction =
                RawTransaction.createTransaction(chainId, nonce, gasLimit, to, value, data,
                        fees1559.maxPriorityFeePerGas, fees1559.maxFeePerGas);

        return sendPendingTransaction(new PendingTransaction(rawTransaction, false), false, false);
    }

    private EthSendTransaction sendPendingTransaction(PendingTransaction pendingTransaction, boolean isAsyncRetry,
                                                      boolean waitForReceipt) {
        EthSendTransaction ethSendTransaction = null;
        String error = null;
        try {
            ethSendTransaction = signAndSend(pendingTransaction.getRawTransaction());
            if (ethSendTransaction == null) {
                log.error("signAndSend returned null: " + pendingTransaction, new NullPointerException());
            } else if (ethSendTransaction.hasError()) {
                error = ethSendTransaction.getError().getMessage();
                log.error("signAndSend returned error '" + error + "' " + pendingTransaction, new RuntimeException());
            } else {
                pendingNonces.add(pendingTransaction.getRawTransaction().getNonce());
                pendingTransaction.setAcceptedToMemPool(ethSendTransaction);
                pendingTransactions.put(ethSendTransaction.getTransactionHash(), pendingTransaction);
                if (waitForReceipt) {
                    try {
                        transactionReceiptProcessor.waitForTransactionReceipt(ethSendTransaction.getTransactionHash());
                    } catch (TransactionException e) {
                        //QueuingTransactionReceiptProcessor never throws in waitForTransactionReceipt
                        return retryTimedOutTransaction(ethSendTransaction.getTransactionHash(), false);
                    } catch (IOException e) {
                        //QueuingTransactionReceiptProcessor never throws in waitForTransactionReceipt
                        log.error("Failed to wait for receipt. Retrying", e);
                        EthSendTransaction retryResult = retryTransaction(pendingTransaction, null, false, true);
                        if (retryResult != null) {
                            return retryResult;
                        }
                    }
                }
                return ethSendTransaction;
            }
        } catch (IOException e) {
            log.error("Exception in signAndSend " + pendingTransaction, e);
        }
        if (isAsyncRetry) {
            String finalError = error;
            Async.defaultExecutorService().execute(() -> retryTransaction(pendingTransaction, finalError, true, true));

        } else {
            EthSendTransaction retryResult = retryTransaction(pendingTransaction, error, false, waitForReceipt);
            if (retryResult != null) {
                return retryResult;
            }
        }
        return ethSendTransaction;
    }

    EthSendTransaction retryTimedOutTransaction(String hash, boolean asyncRetry) {
        PendingTransaction pendingTransaction = pendingTransactions.remove(hash);
        return retryTransaction(pendingTransaction, TRANSACTION_TIMEOUT_ERROR, asyncRetry, true);
    }

    private EthSendTransaction retryTransaction(PendingTransaction pendingTransaction, String error, boolean asyncRetry, boolean waitForReceipt) {
        log.error("Retry due to '" + error + "' tx:" + pendingTransaction);
        if (pendingTransaction.getRetries() > MAX_RETRIES) {
            transactionFailed(pendingTransaction, error);
            return null;
        } else {
            if (error == null) {
                pendingTransaction.retryNoChanges();
            } else if (TRANSACTION_TIMEOUT_ERROR.equals(error) || "transaction underpriced".equals(error)) {
                BigInteger newGasPrice = retryFeeProvider.getNewGasPrice(pendingTransaction.getGasPrice());
                if (TRANSACTION_TIMEOUT_ERROR.equals(error) && pendingTransaction.getRetries() >= UNSTUCK_TRIGGER_RETRIES) {
                    createNonceUnStuckTransactions(newGasPrice);
                }
                pendingTransaction.retryChangeGasPrice(newGasPrice);
            } else {
                error = error.toLowerCase(Locale.ROOT);
                try {
                    if (error.contains(ErrorMsg.INSUFFICIENT_FUNDS)) {
                        transactionFailed(pendingTransaction, error);
                        return null;
                    } else if (error.contains("replacement transaction underpriced")) {
                        if (pendingTransaction.isNonceUnstuck()) {
                            BigInteger newGasPrice = retryFeeProvider.getNewGasPrice(pendingTransaction.getGasPrice());
                            pendingTransaction.retryChangeGasPrice(newGasPrice);
                        } else {
                            retryResetNonce(pendingTransaction);
                        }
                    } else if (error.contains(ErrorMsg.NONCE_TOO_LOW)) {
                        if (pendingTransaction.isNonceUnstuck()) {
                            //success - this nonce was already unstuck
                            return null;
                        } else {
                            EthSendTransaction lastSendResponse = pendingTransaction.getLastSendResponse();
                            if (lastSendResponse != null) {
                                log.info("Nonce too low when transaction was already in the mempool");
                                TransactionReceipt transactionReceipt =
                                        transactionReceiptProcessor.waitForTransactionReceipt(lastSendResponse.getTransactionHash());
                                if (transactionReceiptProcessor instanceof PollingTransactionReceiptProcessor) {
                                    transactionComplete(transactionReceipt);
                                }
                                return lastSendResponse;
                            } else {
                                retryResetNonce(pendingTransaction);
                            }
                        }
                    } else {
                        pendingTransaction.retryNoChanges();
                    }
                } catch (IOException | TransactionException e) {
                    return retryTransaction(pendingTransaction, error, asyncRetry, waitForReceipt);
                }
            }
            return sendPendingTransaction(pendingTransaction, asyncRetry, waitForReceipt);
        }
    }

    private void retryResetNonce(PendingTransaction pendingTransaction) throws IOException {
        try {
            resetNonce();
            pendingTransaction.retryChangeNonce(getCurrentNonce());
        } catch (IOException e) {
            log.error("Failed to reset nonce. Retrying", e);
            pendingTransaction.retryNoChanges();
            throw e;
        }
    }

    private void transactionFailed(PendingTransaction pendingTransaction, String error) {
        pendingNonces.remove(pendingTransaction.getRawTransaction().getNonce());
        if (pendingTransaction.getFailureCallback() != null) {
            pendingTransaction.getFailureCallback().onTransactionFailure(error);
        }
    }

    public void transactionComplete(TransactionReceipt transactionReceipt) {
        transactionComplete(transactionReceipt, true);
    }

    private void transactionComplete(TransactionReceipt transactionReceipt, boolean retryCallback) {
        PendingTransaction pendingTransaction = pendingTransactions.get(transactionReceipt.getTransactionHash());
        if (pendingTransaction == null) {
            log.warn("Transaction already removed from pending set " + transactionReceipt.getTransactionHash());
        } else {
            if (transactionReceiptProcessor instanceof PollingTransactionReceiptProcessor
                    || !retryCallback
                    || pendingTransaction.isNonceUnstuck()
                    || pendingTransaction.getAcceptanceCallback() != null) {
                pendingTransactions.remove(transactionReceipt.getTransactionHash());
                //all nonces before the one of the successful transaction are already used
                pendingNonces.removeIf(n -> n.compareTo(pendingTransaction.getRawTransaction().getNonce()) <= 0);
                if (pendingTransaction.getAcceptanceCallback() != null) {
                    pendingTransaction.getAcceptanceCallback().onAcceptedToBlockchain(transactionReceipt,
                            pendingTransaction.getRawTransaction());
                } else if (!retryCallback) {
                    log.error("Missing callback for transaction receipt");
                }
            } else {
                log.warn("Missing callback for transaction receipt. Wait for it to be set " + transactionReceipt);
                Async.defaultExecutorService().schedule(() -> transactionComplete(transactionReceipt, false), 100, TimeUnit.MILLISECONDS);
            }
        }
    }

    private static class Fees1559 {
        BigInteger maxPriorityFeePerGas;
        BigInteger maxFeePerGas;
    }

    private Fees1559 calculateFees1559(BigInteger gasPrice) throws IOException {
        Fees1559 result = new Fees1559();
        EthBlock ethBlock = web3j.ethGetBlockByNumber(DefaultBlockParameterName.PENDING, false).send();
        String auxBaseFee = ethBlock.getBlock().getBaseFeePerGas();
        BigInteger baseFee = Numeric.decodeQuantity(auxBaseFee);
        //BigInteger baseFee = ethBlock.getBlock().getBaseFeePerGas();
        BigInteger minTipToMiner = gasPrice.divide(BigInteger.valueOf(1000)); //always toss some coins to the miner
        result.maxFeePerGas = gasPrice.max(baseFee.add(minTipToMiner));
        result.maxPriorityFeePerGas = result.maxFeePerGas.subtract(baseFee);
        return result;
    }

    /**
     * Un-stuck nonces which may be blocking us by creating a dummy transaction transferring 0 ETH to ourselves
     *
     * @param gasPrice The latest gas price with which a transaction times out - ensures that the stuck transactions
     *                 will be unblocked
     */
    private void createNonceUnStuckTransactions(BigInteger gasPrice) {
        //get the nonces before the first nonce currently maintained by us
        BigInteger firstKnownNonce = pendingNonces.pollFirst();
        if (firstKnownNonce == null) {
            throw new IllegalStateException("createNonceUnStuckTransactions called without any pending nonces");
        }
        EthGetTransactionCount ethGetTransactionCount;
        try {
            ethGetTransactionCount = web3j.ethGetTransactionCount(credentials.getAddress(), DefaultBlockParameterName.LATEST).send();

            BigInteger firstStuckNonce = ethGetTransactionCount.getTransactionCount();
            for (BigInteger i = firstStuckNonce; i.compareTo(firstKnownNonce) < 0; i = i.add(BigInteger.ONE)) {
                log.warn("Creating transaction to unstuck nonce " + i + "...");
                Fees1559 fees1559 = calculateFees1559(gasPrice);
                //send 0 ETH to self only to replace the transaction at the stuck nonce
                RawTransaction rawTx = RawTransaction.createEtherTransaction(chainId, i, Transfer.GAS_LIMIT,
                        credentials.getAddress(), BigInteger.ZERO,
                        fees1559.maxPriorityFeePerGas, fees1559.maxFeePerGas);
                sendPendingTransaction(
                        new PendingTransaction(rawTx, true), true, true);
            }
        } catch (IOException e) {
            log.error("Failed to unstuck nonce", e);
        }
    }
}
