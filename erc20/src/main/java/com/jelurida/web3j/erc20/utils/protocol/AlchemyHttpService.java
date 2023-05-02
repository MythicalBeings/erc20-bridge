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

package com.jelurida.web3j.erc20.utils.protocol;

import org.web3j.protocol.exceptions.ClientConnectionException;
import org.web3j.protocol.http.HttpService;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ThreadLocalRandom;

/** HttpService for working with <a href="https://alchemy.com/">Alchemy</a> clients. */
public class AlchemyHttpService extends HttpService {

    public static final int MAX_BACKOFF = 60 * 1000;

    public AlchemyHttpService(String url) {
        super(url);
    }

    @Override
    protected InputStream performIO(String s) throws IOException {
        long retries = 0;
        while (true) {
            try {
                return super.performIO(s);
            } catch (ClientConnectionException cce) {
                if (cce.getMessage().startsWith("Invalid response received: 429")) {
                    //see https://docs.alchemy.com/alchemy/documentation/throughput#option-4-exponential-backoff
                    long waitTime = (1L << retries);
                    if (waitTime < MAX_BACKOFF) {
                        waitTime += ThreadLocalRandom.current().nextLong(1000);
                    }
                    try {
                        Thread.sleep(waitTime);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                    retries++;
                    if (retries > 30) {
                        throw cce;
                    }
                } else {
                    throw cce;
                }
            }
        }
    }
}
