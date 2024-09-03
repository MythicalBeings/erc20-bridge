package com.jelurida.web3j.erc20.utils;

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

import com.jelurida.web3j.erc20.utils.txman.RetryFeeProvider;
import org.web3j.protocol.Web3j;

import java.io.IOException;
import java.math.BigInteger;

public class GasPriceEstimator implements RetryFeeProvider {
    private final Web3j web3j;
    private final int initialOverpay;
    private final int retryOverpay;
    public static final long ETH_GAS_PRICE_ESTIMATION_EXPIRATION = 60 * 60;
    private BigInteger ethGasPrice = null;
    private long lastEthGasPriceEstimationTime = 0;

    public GasPriceEstimator(Web3j web3j, int initialOverpay, int retryOverpay) {
        this.web3j = web3j;
        this.initialOverpay = initialOverpay;
        this.retryOverpay = retryOverpay;
    }

    public synchronized BigInteger getEthGasPrice() throws IOException {
        long now = System.currentTimeMillis();
        if (ethGasPrice == null || now - lastEthGasPriceEstimationTime > ETH_GAS_PRICE_ESTIMATION_EXPIRATION * 1000) {
            BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
            BigInteger initialOverpayAmount = gasPrice.multiply(BigInteger.valueOf(this.initialOverpay)).
                    divide(BigInteger.valueOf(100));
            ethGasPrice = gasPrice.add(initialOverpayAmount);
            Utils.log.info("ethGasPrice=" + gasPrice + "+(" + initialOverpayAmount + ")=" + ethGasPrice);
            lastEthGasPriceEstimationTime = now;
        }
        return ethGasPrice;
    }

    @Override
    public synchronized BigInteger getNewGasPrice(BigInteger failedTransactionGasPrice) {
        BigInteger gasPriceIncrease = failedTransactionGasPrice.
                multiply(BigInteger.valueOf(retryOverpay)).divide(BigInteger.valueOf(100));

        BigInteger increasedPrice = failedTransactionGasPrice.add(gasPriceIncrease);

        if (increasedPrice.compareTo(ethGasPrice) > 0) {
            Utils.log.info("Increasing gas price: " + failedTransactionGasPrice + "+" + gasPriceIncrease +
                    "=" + increasedPrice + " > " + ethGasPrice);
            ethGasPrice = increasedPrice;
            lastEthGasPriceEstimationTime = System.currentTimeMillis();
        } else {
            increasedPrice = ethGasPrice;
        }
        return increasedPrice;
    }
}

