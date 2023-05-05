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
import com.jelurida.web3j.erc20.utils.txman.RetryingRawTransactionManager;
import com.jelurida.web3j.generated.IERC20;
import nxt.Tester;
import nxt.addons.JO;
import nxt.http.callers.IssueAssetCall;
import nxt.util.Convert;
import nxt.util.Logger;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.tx.Contract;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import static nxt.blockchain.ChildChain.IGNIS;

public class AssetsErc1155PegTest extends BasePegTest {
    public static final int ETH_FEE_MULTIPLIER = 20;
    private static final long MINTING_CONTRACT_NONCE = 2138;
    protected IERC20 wETH;
    private RetryingRawTransactionManager ebaTransactionManager;
    private RetryingRawTransactionManager senderTransactionManager;

    @Before
    public void beforeTest() throws Exception {
        super.beforeTest();

        String assetId = issueAsset(BOB, 10000);
        Logger.logInfoMessage("TESTING | beforeTest | assetId: "+ assetId);
        paramsJo.put("assetId", assetId);
        Logger.logInfoMessage("TESTING | beforeTest | paramsJo.assetId: "+ paramsJo.getString("assetId"));

        setRunnerConfig(configJo.toJSONString().getBytes());
        generateBlock();

        ebaTransactionManager = createTransactionManager(ethBlockedAcc);
        senderTransactionManager = createTransactionManager(ethDeployAcc);

        wETH = IERC20.load(paramsJo.getString("contractAddress"), web3j, senderTransactionManager, createCurrentPriceGasProvider(web3j, BigInteger.valueOf(4_000_000)));
        Logger.logInfoMessage("TESTING | beforeTest | wETH Address: "+ wETH.getContractAddress());
    }

    public static final int EXPECTED_UNWRAPS = 1;
    @Test
    public void test(){
        try {
        Logger.logInfoMessage("--------------------------------------------");
        // 1.- Enviar desde wallet a EDA
        Tester wrapper = ALICE;
        String wrapDepositAddress = getWrapDepositAddress(wrapper);
        Logger.logInfoMessage("TESTING | test | Deposit address: "+ wrapDepositAddress);
        Logger.logInfoMessage("--------------------------------------------");

        TransactionReceipt sendToWrapTx = wETH.transfer(wrapDepositAddress, new BigInteger("1000000000000000000")).send();

        Assert.assertTrue(sendToWrapTx.isStatusOK());

        Logger.logInfoMessage("--------------------------------------------");
        // Flujo EVM a Ardor
            // assetId is null, why? Setting before.
        processWraps(wrapper, EXPECTED_UNWRAPS, 0, 0);

        List<String> fullHashes = waitForUnconfirmedAssetTransfers(wrapper, EXPECTED_UNWRAPS);
        generateBlock();
        confirmArdorTransactions(fullHashes);
        processWraps(wrapper, 0, 0, EXPECTED_UNWRAPS);

        // TODO: Unwrap - Send Ardor to EVM

        } catch (Exception e) {
            Logger.logInfoMessage("MB-ERC20 | test | WRAPPING ERROR in CATCH: " + e.getMessage());
        }
    }

    private List<JO> getWrappingLog() {
        return contractRequest("getWrappingLog").callNoError().getJoList("log");
    }

    @NotNull
    private ContractGasProvider createCurrentPriceGasProvider(Web3j web3j, BigInteger gasLimit) throws IOException {
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
        return new StaticGasProvider(gasPrice, gasLimit);
    }


    private String issueAsset(Tester assetIssuer, int quantity) {
        JO issueResult = IssueAssetCall.create(IGNIS.getId())
                .privateKey(assetIssuer.getPrivateKey())
                .feeNQT(20 * IGNIS.ONE_COIN).name("testA").description("Test A")
                .quantityQNT(quantity).decimals(8).callNoError();
        return Tester.responseToStringId(issueResult);
    }

    /**
     * Stolen from https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed
     * @param address Account address
     * @param nonce Account nonce
     * @return Contract address if generated by certain account and nonce
     */
    private String calculateContractAddress(String address, long nonce){
        byte[] addressAsBytes = Numeric.hexStringToByteArray(address);

        byte[] calculatedAddressAsBytes =
                Hash.sha3(RlpEncoder.encode(
                        new RlpList(
                                RlpString.create(addressAsBytes),
                                RlpString.create((nonce)))));

        calculatedAddressAsBytes = Arrays.copyOfRange(calculatedAddressAsBytes,
                12, calculatedAddressAsBytes.length);
        return Numeric.toHexString(calculatedAddressAsBytes);
    }

}