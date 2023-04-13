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

package com.jelurida.web3j.utils.txman;

import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.transaction.type.Transaction1559;
import org.web3j.protocol.core.methods.response.EthSendTransaction;

import java.math.BigInteger;

public class PendingTransaction {
    private final boolean isNonceUnstuck;
    private RawTransaction rawTransaction;
    private int retries;
    private EthSendTransaction lastSendResponse;

    private AcceptanceCallback acceptanceCallback;
    private FailureCallback failureCallback;

    public PendingTransaction(RawTransaction transaction, boolean isNonceUnstuck) {
        this.rawTransaction = transaction;
        this.isNonceUnstuck = isNonceUnstuck;
    }

    public RawTransaction getRawTransaction() {
        return rawTransaction;
    }

    public boolean isNonceUnstuck() {
        return isNonceUnstuck;
    }

    public void setAcceptedToMemPool(EthSendTransaction ethSendTransaction) {
        lastSendResponse = ethSendTransaction;
    }

    public EthSendTransaction getLastSendResponse() {
        return lastSendResponse;
    }

    private Transaction1559 getRawTx1559() {
        return (Transaction1559) this.rawTransaction.getTransaction();
    }

    public BigInteger getGasPrice() {
        return getRawTx1559().getMaxFeePerGas();
    }

    void retryChangeNonce(BigInteger newNonce) {
        if (lastSendResponse != null) {
            throw new IllegalStateException("Cannot change nonce. Transaction is already accepted to the mempool");
        }
        Transaction1559 rawTx1559 = getRawTx1559();
        retryTransaction(RawTransaction.createTransaction(rawTx1559.getChainId(), newNonce,
                rawTx1559.getGasLimit(), rawTx1559.getTo(), rawTx1559.getValue(),
                rawTx1559.getData(), rawTx1559.getMaxPriorityFeePerGas(), rawTx1559.getMaxFeePerGas()));
    }

    void retryChangeGasPrice(BigInteger newGasPrice) {
        Transaction1559 rawTx1559 = getRawTx1559();
        BigInteger baseFee = rawTx1559.getMaxFeePerGas().subtract(rawTx1559.getMaxPriorityFeePerGas());
        retryTransaction(RawTransaction.createTransaction(rawTx1559.getChainId(), rawTx1559.getNonce(),
                rawTx1559.getGasLimit(), rawTx1559.getTo(), rawTx1559.getValue(),
                rawTx1559.getData(), newGasPrice.subtract(baseFee), newGasPrice));
    }

    void retryNoChanges() {
        retryTransaction(this.rawTransaction);
    }

    private void retryTransaction(RawTransaction newRawTransaction) {
        this.rawTransaction = newRawTransaction;
        retries++;
    }

    public int getRetries() {
        return retries;
    }

    public void setCallbacks(AcceptanceCallback acceptanceCallback, FailureCallback failureCallback) {
        this.acceptanceCallback = acceptanceCallback;
        this.failureCallback = failureCallback;
    }

    public AcceptanceCallback getAcceptanceCallback() {
        return acceptanceCallback;
    }

    public FailureCallback getFailureCallback() {
        return failureCallback;
    }

    @Override
    public String toString() {
        return "PendingTransaction{" +
                "isNonceUnstuck=" + isNonceUnstuck +
                (lastSendResponse == null ? "" : ", lastMemPoolHash='" + lastSendResponse.getTransactionHash() + '\'') +
                ", retries=" + retries +
                ", nonce=" + rawTransaction.getNonce() +
                ", to=" + rawTransaction.getTo() +
                ", gasPrice=" + getGasPrice() +
                ", acceptanceCallback=" + acceptanceCallback +
                ", failureCallback=" + failureCallback +
                '}';
    }
}
