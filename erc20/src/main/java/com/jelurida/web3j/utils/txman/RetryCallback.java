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

import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.tx.response.Callback;

public class RetryCallback implements Callback {
    private RetryingRawTransactionManager transactionManager;

    @Override
    public void accept(TransactionReceipt transactionReceipt) {
        transactionManager.transactionComplete(transactionReceipt);
    }

    @Override
    public void exception(Exception e) {
        RetryingRawTransactionManager.log.error("Exception when creating Ethereum transaction", e);
        if (e instanceof TransactionException) {
            ((TransactionException) e).getTransactionHash().ifPresent(hash -> transactionManager.retryTimedOutTransaction(hash, true));
        }
    }

    public RetryingRawTransactionManager getTransactionManager() {
        return transactionManager;
    }

    public void setTransactionManager(RetryingRawTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }
}
