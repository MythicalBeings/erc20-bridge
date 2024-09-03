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

package com.jelurida.web3j.erc20.utils;

import com.jelurida.web3j.generated.IERC20;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.gas.StaticGasProvider;

import java.io.IOException;
import java.math.BigInteger;

public class TransactionalContract {
    private final Web3j web3j;
    private final IERC20 erc20WrappedContract;
    private BigInteger lastSetGasPrice = null;

    public TransactionalContract(String contractAddress, Web3j web3j,
                                 TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        this.web3j = web3j;
        erc20WrappedContract = IERC20.load(contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public <T extends Contract> T getReadOnly(Class<T> contractClass) {
        return (T) erc20WrappedContract;
    }

    public <T extends Contract> T getForTransaction(Class<T> contractClass,
                                                    String senderAddress, BigInteger ethGasPrice) throws IOException, IOException {
        T result = (T) erc20WrappedContract;

        if (!ethGasPrice.equals(lastSetGasPrice)) {
            lastSetGasPrice = ethGasPrice;
            BigInteger ebaBalance = web3j.ethGetBalance(senderAddress, DefaultBlockParameterName.LATEST).send().getBalance();
            result.setGasProvider(new StaticGasProvider(ethGasPrice,
                    DefaultGasProvider.GAS_LIMIT.min(ebaBalance.divide(ethGasPrice).divide(BigInteger.valueOf(2)))));
        }
        return result;
    }

    /*
    public <T extends Contract> T getReadOnly(Class<T> contractClass) {
        return (T) erc20WrappedContract;
    }

    public <T extends Contract> T getForTransaction(Class<T> contractClass,
                                                    String senderAddress, BigInteger ethGasPrice) throws IOException {
        T result = (T) erc20WrappedContract;
        if (!ethGasPrice.equals(lastSetGasPrice)) {
            lastSetGasPrice = ethGasPrice;
            BigInteger ebaBalance = web3j.ethGetBalance(senderAddress, DefaultBlockParameterName.LATEST).send().getBalance();
            result.setGasProvider(new StaticGasProvider(ethGasPrice,
                    DefaultGasProvider.GAS_LIMIT.min(ebaBalance.divide(ethGasPrice).divide(BigInteger.valueOf(2)))));
        }
        return result;
    }

     */
}
