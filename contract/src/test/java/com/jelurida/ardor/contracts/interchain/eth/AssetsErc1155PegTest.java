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
import com.jelurida.web3j.utils.Utils;
import com.jelurida.web3j.utils.txman.RetryingRawTransactionManager;
import nxt.Constants;
import nxt.Nxt;
import nxt.Tester;
import nxt.addons.JO;
import nxt.blockchain.TransactionProcessorImpl;
import nxt.http.APICall;
import nxt.http.callers.GetTransactionCall;
import nxt.http.callers.IssueAssetCall;
import nxt.http.callers.TransferAssetCall;
import nxt.util.Convert;
import nxt.util.JSON;
import nxt.util.Logger;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.Transfer;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static nxt.blockchain.ChildChain.IGNIS;

public class AssetsErc1155PegTest extends BasePegTest {
    public static final int ETH_FEE_MULTIPLIER = 20;
    private static final long MINTING_CONTRACT_NONCE = 2138;
    protected BRIDGE_ERC20 erc1155;
    private RetryingRawTransactionManager ebaTransactionManager;

    @Before
    public void beforeTest() throws Exception {
        super.beforeTest();
        //erc1155 = deployOrLoadErc1155Contract();
    }

    @Test
    public void test(){
        JO pegAddresses = contractRequest("getPegAddresses").callNoError();
    }

    @NotNull
    private Credentials generateTesterEthAcc(Tester tester) {
        return AssetsErc20.getCredentialsFromSecret("User's secret on Eth side " + tester.getSecretPhrase());
    }

    private List<JO> getWrappingLog() {
        return contractRequest("getWrappingLog").callNoError().getJoList("log");
    }

    private BRIDGE_ERC20 deployOrLoadErc1155Contract() throws Exception {
        ebaTransactionManager = createTransactionManager(ethBlockedAcc);
        ContractGasProvider gasProvider = createCurrentPriceGasProvider(web3j, BigInteger.valueOf(4_000_000));
        String contractAddress = calculateContractAddress(ethBlockedAcc.getAddress(), MINTING_CONTRACT_NONCE);
        BRIDGE_ERC20 contract = BRIDGE_ERC20.load(contractAddress, web3j, ebaTransactionManager,
                gasProvider);
        if (contractNeedsDeployment(contract)) {
            paramsJo.put("contractAddress", null);
            setRunnerConfig(configJo.toJSONString().getBytes());
            JO result = contractRequest("deployEthContract")
                    .param("uri", "http://jelurida.com/nft/{id}.json")
                    .param("name", "Ardor To Polygon Test Contract").callNoError();
            contractAddress = result.getString("ethContractAddress");
        }
        paramsJo.put("contractAddress", contractAddress);
        contract = BRIDGE_ERC20.load(contractAddress, web3j, ebaTransactionManager,
                gasProvider);
        return contract;
    }

    private boolean contractNeedsDeployment(Contract contract) throws IOException {
        if (!contract.isValid()) {
            BigInteger ebaNonce = web3j.ethGetTransactionCount(ethBlockedAcc.getAddress(), DefaultBlockParameterName.LATEST)
                    .send().getTransactionCount();
            if (!ebaNonce.equals(BigInteger.valueOf(MINTING_CONTRACT_NONCE))) {
                throw new IllegalStateException("Account " + ethBlockedAcc.getAddress() + " transaction at nonce " +
                        MINTING_CONTRACT_NONCE + " is not a valid contract (or does not match the currently compiled binaries)." +
                        " Change MINTING_CONTRACT_NONCE to " + ebaNonce + " to deploy the currently compiled binaries");
            }
            return true;
        }
        return false;
    }

    @NotNull
    private ContractGasProvider createCurrentPriceGasProvider(Web3j web3j, BigInteger gasLimit) throws IOException {
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
        return new StaticGasProvider(gasPrice, gasLimit);
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