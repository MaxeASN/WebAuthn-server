package com.mih.webauthn.demo;

import COSE.CoseException;
import COSE.OneKey;
import com.google.common.hash.Hashing;
import com.mih.webauthn.demo.constant.BlockchainConst;
import com.mih.webauthn.demo.constant.ERC20Const;
import com.mih.webauthn.demo.constant.ERC4337Const;
import com.mih.webauthn.demo.domain.Transaction;
import com.mih.webauthn.demo.domain.TransactionRepo;
import com.mih.webauthn.demo.domain.Wallet;
import com.mih.webauthn.demo.domain.WalletRepo;
import com.mih.webauthn.demo.domain.dto.L1RpcParams;
import com.mih.webauthn.demo.domain.dto.L1RpcResponse;
import com.mih.webauthn.demo.domain.erc4337.UserOperation;
import com.mih.webauthn.demo.domain.vo.TransactionParams;
import com.mih.webauthn.demo.exception.EthCallException;
import com.mih.webauthn.demo.exception.TransactionFailedException;
import com.mih.webauthn.demo.service.CredentialService;
import com.mih.webauthn.demo.service.L1RpcService;
import com.mih.webauthn.demo.utils.AESUtils;
import com.mih.webauthn.demo.utils.ERC4337Utils;
import com.mih.webauthn.demo.utils.EthUtils;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.ByteArray;
import feign.Feign;
import feign.Request;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import io.github.webauthn.domain.WebAuthnCredentialsRepository;
import io.github.webauthn.domain.WebAuthnUserRepository;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.JpaWebAuthnUser;
import io.github.webauthn.jpa.WebAuthnCredentialsSpringDataRepository;
import io.github.webauthn.jpa.WebAuthnUserSpringDataRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@SpringBootTest
class WebauthnDemoApplicationTests {
//	private static final String PRIVATE_KEY_PEM = "C:\\Users\\huagao\\Downloads\\privateKey.pem";
//	@Autowired
//	private WebAuthnUserSpringDataRepository userRepository;
//
//	@Autowired
//	private WebAuthnCredentialsSpringDataRepository credentialsRepository;
//
//	@Autowired
//	private WebAuthnUserRepository<JpaWebAuthnUser> webAuthnUserRepository;
//
//	@Autowired
//	private WebAuthnCredentialsRepository<JpaWebAuthnCredentials> webAuthnCredentialsRepository;
//
//	@Autowired
//	private Web3j web3j;
//
//	@Autowired
//	private EthUtils ethUtils;
//
//	@Autowired
//	private WalletRepo walletRepo;
//
//	@Autowired
//	private ERC4337Utils erc4337Utils;
//
//	@Autowired
//	private TransactionRepo transactionRepo;
//
//	@Autowired
//	private CredentialService credentialService;
//
//	@Test
//	void contextLoads() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//		JpaWebAuthnUser chen = userRepository.findByUsername("chen").get();
//		JpaWebAuthnCredentials credential = credentialsRepository.findAllByAppUserId(chen.getId()).get(0);
//		CBORObject cose = CBORObject.DecodeFromBytes(credential.getPublicKeyCose());
//		PublicKey key = (ECPublicKey) new OneKey(cose).AsPublicKey();
//		System.out.println();
//
//		ByteArray clientDataJson = new ByteArray(Base64.getUrlDecoder().decode("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVNRSS1jR0l0TGNWOG1TQUYzek56YUl4clhBdGZMMVp0d1VwM1BKUjJVZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"));
//		ByteArray authenticatorData = new ByteArray(Base64.getUrlDecoder().decode("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAg"));
//		ByteArray clientDataJsonHash = new ByteArray(Hashing.sha256().hashBytes(clientDataJson.getBytes()).asBytes());
//		byte[] signatureBytes = Base64.getUrlDecoder().decode("MEQCIB3azAhch_2icxdA2VyM0he8C4cMSfoyz5Bg3TLt5U6nAiAtqaNGcooasj8p3QCjWhWbWNAzJnqVafmpitchL4LXzQ");
//		ByteArray signedBytes = authenticatorData.concat(clientDataJsonHash);
//		//System.out.println(Base64.getUrlEncoder().encodeToString(signedBytes.getBytes()));
//
//		//验证签名
//		Signature signature = Signature.getInstance("SHA256withECDSA");
//		signature.initVerify(key);
//		signature.update(signedBytes.getBytes());
//		System.out.println(signature.verify(signatureBytes));
//
//	}
//
//	@Test
//	public void testEthCall() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(102L).get(0);
//		UserOperation userOperation = new UserOperation();
//		userOperation.setAddress("0x6D4181bA47d2341C3491124ADe939dd5A6F76eaE");
//		userOperation.setCallGasLimit(new BigInteger("123"));
//		DynamicStruct userOpStruct = ERC4337Utils.createUserOpStruct(userOperation);
//		Function function = new Function(
//				"testInputUserOp",
//				Arrays.asList(new DynamicArray(DynamicStruct.class, userOpStruct), new Address("0xefad54D8BdaA159C74eec23167EB310F8c7bc433")),
//				Arrays.asList(new TypeReference<Uint256>() {}));
//		List<Type> typeList = ethUtils.ethCall("0xeDcFCc97aC7644512DfEE7d2de9539ff1b09f094", function);
//		System.out.println("------------------");
//	}
//
//	@Test
//	public void testSignature() throws SignatureException {
//		Wallet wallet = walletRepo.findByAppUserId(94L).iterator().next();
//		String privateKey = AESUtils.decrypt(wallet.getPrivateKey());
//
//		// 使用ECKeyPair对象创建一个Credentials对象，用于管理公私钥
//		Credentials credentials = Credentials.create(privateKey);
//
//// 需要签名的消息内容
//		String message = "hello world";
//
//		ECKeyPair keyPair = credentials.getEcKeyPair();
//
//// 对消息进行签名
//		Sign.SignatureData signature = Sign.signMessage(message.getBytes(), keyPair);
//
//
//// 在Solidity中还原签名者地址
//		String signerAddress = "0x" + Keys.getAddress(Sign.signedMessageToKey(message.getBytes(), signature));
//		System.out.println(signerAddress);
//
//	}
//
//	@Test
//	public void createInitCode() throws IOException {
//		byte[] fidoPublicKey = Numeric.hexStringToByteArray("4554480000000000000000000000000000000000000000000000000000000000");
//		byte[] initCode = erc4337Utils.createInitCode(fidoPublicKey, 20);
//		System.out.println(Numeric.toHexString(initCode));
//	}
//
//	@Test
//	public void testSendContract() throws IOException {
//		UserOperation userOperation = new UserOperation();
//		userOperation.setAddress("0xefad54D8BdaA159C74eec23167EB310F8c7bc433");
//		userOperation.setCallGasLimit(new BigInteger("123"));
//		DynamicStruct userOpStruct = ERC4337Utils.createUserOpStruct(userOperation);
//		Wallet wallet = walletRepo.findByAppUserId(95L).iterator().next();
//		String transactionHash = ethUtils.sendContract(wallet,
//				"0x4Fc8d9097260bA6Ae450FE0FdeAE7EEd3142Ccf4",
//				"testInputUserOp",
//				List.of(new DynamicArray(DynamicStruct.class, userOpStruct)),
//				List.of(new TypeReference<Uint256>() {}));
//		System.out.println(transactionHash);
//	}
//
//	@Test
//	public void getOutputFromHash() throws IOException {
//		String transactionHash = "0xa47c8f7108fd77a49b0a1b164c9606f8dfc732f677dc68b747ba38fcd9bad2bc"; // 要查询的交易哈希
//		EthGetTransactionReceipt receipt = web3j.ethGetTransactionReceipt(transactionHash).send();
//		if (receipt.getTransactionReceipt().isPresent() && receipt.getResult().isStatusOK()) {
//			TransactionReceipt transactionReceipt = receipt.getTransactionReceipt().get();
//			List<Log> logs = transactionReceipt.getLogs(); // 获取交易日志
//			String contractAddress = transactionReceipt.getContractAddress(); // 获取合约地址
//			String status = transactionReceipt.getStatus(); // 获取交易状态（成功或失败）
//			// 根据合约ABI解析日志数据以获取返回值
//		} else {
//			System.out.println("找不到交易收据");
//		}
//	}
//
//	@Test
//	public void putUserOpTo4337() throws IOException {
//		Wallet wallet = walletRepo.findByAppUserId(248L).iterator().next();
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(248L).get(0);
//		System.out.println(Numeric.toHexString(credentials.getPublicKeyCose()));
//
//		erc4337Utils.registerSoulAccount(wallet, credentials.getPublicKeyCose());
//	}
//
//	@Test
//	public void getUserOpHash() throws IOException {
//		UserOperation userOperation = new UserOperation();
//		userOperation.setAddress("0xCf9D201bC4455B385652937Bf030564331367667");
//		DynamicStruct userOpStruct = ERC4337Utils.createUserOpStruct(userOperation);
//		List<Type> results = ethUtils.ethCall(ERC4337Const.ENTRYPOINT_ADDRESS,
//				ERC4337Const.GET_USEROPERATION_HASH,
//				List.of(userOpStruct),
//				List.of(new TypeReference<Bytes32>() {}));
//		if(results.size() == 0){
//			throw new EthCallException("获取UserOperation的hash值失败");
//		}
//	}
//
//	@Test
//	public void testSignAndVerifySign() throws IOException {
//		Wallet wallet = walletRepo.findByAppUserId(94L).iterator().next();
//		String privateKey = AESUtils.decrypt(wallet.getPrivateKey());
//
//		// 使用ECKeyPair对象创建一个Credentials对象，用于管理公私钥
//		Credentials credentials = Credentials.create(privateKey);
//
//// 需要签名的消息内容
//		String message = "123";
//
//		ECKeyPair keyPair = credentials.getEcKeyPair();
//
//// 对消息进行签名
//		Sign.SignatureData signature = Sign.signMessage(message.getBytes(), keyPair);
//
//		byte[] signatureBytes = new byte[65];
//		System.arraycopy(signature.getR(), 0, signatureBytes, 0, 32);
//		System.arraycopy(signature.getS(), 0, signatureBytes, 32, 32);
//		System.arraycopy(signature.getV(), 0, signatureBytes, 64, 1);
//
//		List<Type> typeList = ethUtils.ethCall("0x0d43B1B02a13aE6d79566906585c16B8C89c5Ec0",
//				"validateSignature",
//				Arrays.asList(new Utf8String("123"), new DynamicBytes(signatureBytes)),
//				List.of(new TypeReference<Bool>() {
//				}));
//		System.out.println("------------");
//
//	}
//
//	@Test
//	public void testCreateSoulAccountAddress() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(248L).get(0);
//		byte[] publicKey = credentials.getPublicKeyCose();
//		List<Type> typeList = ethUtils.ethCall(ERC4337Const.FACTORY_ADDRESS,
//				"createAccount",
//				Arrays.asList(new DynamicBytes(publicKey),
//						new Uint256(123)),
//				List.of(new TypeReference<Address>() {})
//		);
//		System.out.println("-------");
//	}
//
//	@Test
//	public void testGasLimit() throws IOException {
//		//Wallet wallet = walletRepo.findByAppUserId(94L).iterator().next();
//		byte[] fidoPublicKey = Numeric.hexStringToByteArray("4554480000000000000000000000000000000000000000000000000000000012");
//		UserOperation userOperation = new UserOperation();
//		userOperation.setAddress("0xCeD19750dE3435eFc25b36932392e8BccDC1Edb7");
//		userOperation.setNonce(new BigInteger("0"));
//		userOperation.setInitCode(Numeric.hexStringToByteArray("6a61a1e3c1c329d01f909e7767760473d65c71700fd8377b0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000204554480000000000000000000000000000000000000000000000000000000012"));
//		userOperation.setVerificationGasLimit(new BigInteger("522496"));
//		userOperation.setPreVerificationGas(new BigInteger("21000"));
//		userOperation.setMaxFeePerGas(new BigInteger("1000000050"));
//		userOperation.setMaxPriorityFeePerGas(new BigInteger("1000000000"));
//		userOperation.setFidoPublickey(fidoPublicKey);
//		DynamicStruct userOpStruct = ERC4337Utils.createUserOpStruct(userOperation);
//
//		Function function = new Function(ERC4337Const.HANDLE_USEROPERATION,
//				Arrays.asList(new DynamicArray<>(DynamicStruct.class, userOpStruct), new Address("0xdf08a214a807640dfc9da47f2f83591eed40e3c1")),
//				Collections.emptyList());
//		String data = FunctionEncoder.encode(function);
////		String data = "0xf02889490000000000000000000000000000000000000000000000000000000000000040000000000000000000000000df08a214a807640dfc9da47f2f83591eed40e3c100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000ced19750de3435efc25b36932392e8bccdc1edb70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f9000000000000000000000000000000000000000000000000000000000000005208000000000000000000000000000000000000000000000000000000003b9aca32000000000000000000000000000000000000000000000000000000003b9aca000000000000000000000000000000000000000000000000000000000000000260000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000000986a61a1e3c1c329d01f909e7767760473d65c71700fd8377b0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000204554480000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002045544800000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000000";
//		System.out.println(data);
//		BigInteger gasLimit = web3j
//				.ethEstimateGas(
//						new org.web3j.protocol.core.methods.request.Transaction("0xdf08a214a807640dfc9da47f2f83591eed40e3c1", null, null,
//								null, "0xba77eaa474c1b2c3ba1a754c6a765796a13ac3d8", null, data)).send().getAmountUsed();
//		System.out.println(gasLimit);
//
//	}
//
//	@Test
//	public void testGetContractAddressByPbKey() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(248L).get(0);
//		List<Type> typeList = ethUtils.ethCall(ERC4337Const.ACCOUNT_LIST_ADDRESS,
//				"Get",
//				List.of(new DynamicBytes(credentials.getPublicKeyCose())),
//				Arrays.asList(new TypeReference<Bool>() {}, new TypeReference<Address>() {}));
//		System.out.println("-----------");
//	}
//
//	@Test
//	public void testGetNonce() throws IOException {
//		List<Type> typeList = ethUtils.ethCall("0xd7c6dcd6b8ab800e370188b5943a66f109753e6b",
//				ERC4337Const.GET_NONCE,
//				Collections.emptyList(),
//				List.of(new TypeReference<Uint256>() {
//				}));
//		System.out.println("-----------");
//	}
//
//	@Test
//	public void testTransferToken() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(105L).get(0);
//
//		Wallet wallet = walletRepo.findByAppUserId(94L).iterator().next();
//
//		TransactionParams transactionParams = new TransactionParams();
//		transactionParams.setCoin(ERC20Const.COIN_MAIN);
//		transactionParams.setAmount(new BigDecimal("0.001"));
//		transactionParams.setToAddress("0x7B2770e67C3af189D30FBC890a1ADBD57B08f020");
//
//		erc4337Utils.sendTransaction(wallet, transactionParams, credentials.getCredentialId());
//	}
//
//	@Test
//	public void testEvent(){
//		Web3j web3j = Web3j.build(new HttpService("http://localhost:8545"));
//		String contractAddress = "0x7E79290aEAb40626B8a5c9Cb6086F7E3554c767E";
//		//添加要监听事件的主题，和合约地址
//		EthFilter filter = new EthFilter(DefaultBlockParameterName.EARLIEST,DefaultBlockParameterName.LATEST, contractAddress);
//		web3j.ethLogFlowable(filter).subscribe(log -> {
//			String transactionHash = log.getTransactionHash();
//			System.out.println(transactionHash);
//		});
//	}
//
//	@Test
//	public void getBalance() throws IOException {
//		EthGetBalance balance = web3j.ethGetBalance("0xd6AF81D4b9E9C3fA2044E2FE3b7c052cA312575E", DefaultBlockParameterName.LATEST).send();
//		System.out.println(Convert.fromWei(balance.getBalance().toString(), Convert.Unit.ETHER));
//	}
//
//	@Test
//	public void testTransferL1TokenOnL2() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(248L).get(0);
//		Wallet wallet = walletRepo.findByAppUserId(248L).iterator().next();
//		String accountAddress = wallet.getContractAddress();
//
//		UserOperation userOperation = new UserOperation();
//		userOperation.setAddress(accountAddress);
//		BigInteger nonce = erc4337Utils.getAccountNonce(accountAddress);
//		userOperation.setNonce(nonce);
//		BigDecimal value = Convert.toWei("0.001", Convert.Unit.ETHER);
//		Function callData = new Function(
//				"L1transfer",
//				Arrays.asList(new Uint64(1), new Address("0xd6af81d4b9e9c3fa2044e2fe3b7c052ca312575e"), new Address("0x6D4181bA47d2341C3491124ADe939dd5A6F76eaE"), new Uint256(value.longValue()), DynamicBytes.DEFAULT),
//				Collections.emptyList()
//		);
//        System.out.println(FunctionEncoder.encode(callData));
//		byte[] callDataBytes = Numeric.hexStringToByteArray(FunctionEncoder.encode(callData));
//		userOperation.setCallData(callDataBytes);
//		userOperation.setCallGasLimit(new BigInteger("500000"));
//		userOperation.setVerificationGasLimit(new BigInteger("300000"));
//		userOperation.setPreVerificationGas(new BigInteger("21000"));
//		userOperation.setMaxFeePerGas(new BigInteger("1000000050"));
//		userOperation.setMaxPriorityFeePerGas(new BigInteger("1000000000"));
//		userOperation.setFidoPublickey(credentials.getPublicKeyCose());
//		DynamicStruct userOpStruct = ERC4337Utils.createUserOpStruct(userOperation);
//
//		String transactionHash = ethUtils.sendContract(wallet,
//				ERC4337Const.ENTRYPOINT_ADDRESS,
//				ERC4337Const.HANDLE_USEROPERATION,
//				Arrays.asList(new DynamicArray(DynamicStruct.class, userOpStruct), new Address(wallet.getAddress())),
//				Collections.emptyList());
//		System.out.println(transactionHash);
//	}
//
//	//新交易测试
//	@Test
//	public void testNewTransferL1TokenOnL2() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(248L).get(0);
//		Wallet wallet = walletRepo.findByAppUserId(248L).iterator().next();
//		String accountAddress = wallet.getContractAddress();
//
//		UserOperation userOperation = new UserOperation();
//		userOperation.setAddress(accountAddress);
//		BigInteger nonce = erc4337Utils.getAccountNonce(accountAddress);
//		userOperation.setNonce(nonce);
//		BigDecimal value = Convert.toWei("0.001", Convert.Unit.ETHER);
//		byte[] l1TxData = erc4337Utils.createL1TxData(5, ERC20Const.COIN_MAIN, "0x6b4825a86698c4cf967a35c6e034c9fa76465383", "0x6D4181bA47d2341C3491124ADe939dd5A6F76eaE", value, "");
//		System.out.println(Numeric.toHexString(l1TxData));
//		userOperation.setL1TxData(l1TxData);
//		userOperation.setCallGasLimit(new BigInteger("500000"));
//		userOperation.setVerificationGasLimit(new BigInteger("300000"));
//		userOperation.setPreVerificationGas(new BigInteger("21000"));
//		userOperation.setMaxFeePerGas(new BigInteger("1000000050"));
//		userOperation.setMaxPriorityFeePerGas(new BigInteger("1000000000"));
//		userOperation.setFidoPublickey(credentials.getPublicKeyCose());
////		userOperation.setPaymasterAndData(erc4337Utils.createPaymasterAndData());
//		DynamicStruct userOpStruct = ERC4337Utils.createUserOpStruct(userOperation);
//
//		String transactionHash = ethUtils.sendContract(wallet,
//				ERC4337Const.ENTRYPOINT_ADDRESS,
//				ERC4337Const.HANDLE_USEROPERATION,
//				Arrays.asList(new DynamicArray(DynamicStruct.class, userOpStruct), new Address(wallet.getAddress())),
//				Collections.emptyList());
//		System.out.println(transactionHash);
//	}
//
//	@Test
//	public void testRegister() throws IOException {
//		JpaWebAuthnCredentials credentials = webAuthnCredentialsRepository.findAllByAppUserId(248L).get(0);
//		System.out.println(Numeric.toHexString(credentials.getPublicKeyCose()));
//		Wallet wallet = walletRepo.findByAppUserId(248L).iterator().next();
//		String accountAddress = erc4337Utils.createSoulAccount(credentials.getPublicKeyCose(), ERC4337Const.ACCOUNT_SALT);
//		String registerHash;
//		try {
//			DynamicStruct registerUserOp = erc4337Utils.createRegisterUserOp(accountAddress, credentials.getPublicKeyCose());
//			registerHash = ethUtils.sendContract(wallet,
//					ERC4337Const.ENTRYPOINT_ADDRESS,
//					ERC4337Const.HANDLE_USEROPERATION,
//					Arrays.asList(new DynamicArray(DynamicStruct.class, registerUserOp), new Address(wallet.getAddress())),
//					Collections.emptyList());
//		} catch (Exception e) {
//			System.out.println("注册SoulAccount失败:" + e.getMessage());
//			throw new TransactionFailedException("注册SoulAccount失败");
//		}
//		System.out.println("注册hash：" + registerHash);
//	}
//
//	@Test
//	public void getL1Hash() throws IOException {
//		ethUtils.ethCall("0x20e3b93d3a62c0120ed9591925cf269ed5303ccf",
//				"getL1Txhash",
//				Arrays.asList(new Address("0xd6af81d4b9e9c3fa2044e2fe3b7c052ca312575e"), new Uint64(3)),
//				List.of(new TypeReference<DynamicBytes>() {}));
//	}
//
//	@Test
//	public void getSequence() throws IOException {
//		ethUtils.ethCall("0x20e3b93d3a62c0120ed9591925cf269ed5303ccf",
//				"SequenceNumber",
//				List.of(new Address("0xd6af81d4b9e9c3fa2044e2fe3b7c052ca312575e")),
//				List.of(new TypeReference<Uint64>() {}));
//	}
//
//	@Test
//	public void getTxsInfo() throws IOException {
//		ethUtils.ethCall("0x20e3b93d3a62c0120ed9591925cf269ed5303ccf",
//				"TxsInfo",
//				List.of(new Address("0xd6af81d4b9e9c3fa2044e2fe3b7c052ca312575e"), new Uint64(3)),
//				List.of(new TypeReference<DynamicStruct>() {}));
//	}
//
//	@Test
//	public void testSaveTransaction(){
//		com.mih.webauthn.demo.domain.Transaction transaction = new Transaction(120L, "1", 1, 2L, "0x6D4181bA47d2341C3491124ADe939dd5A6F76eaE",
//				new BigDecimal("0.01"), "0x1234");
//		transactionRepo.save(transaction);
//	}
//
//	@Test
//	public void getTransaction() throws IOException {
//		EthGetTransactionReceipt send = web3j.ethGetTransactionReceipt("0x645566b8ff3b12dd5ea8b3b5bd6f0fc3bd9e5f0b427c0508e3ba46c0c5c157a3").send();
//		System.out.println(123);
//	}
//
//	@Test
//	public void printNonce() throws IOException {
//		System.out.println(web3j.ethGetTransactionCount(BlockchainConst.MINER_ADDRESS, DefaultBlockParameterName.LATEST).send().getTransactionCount());
//	}
//
//	@Test
//	public void createL1Address() throws InterruptedException {
//		L1RpcService l1RpcService = Feign.builder()
//				.encoder(new JacksonEncoder())
//				.decoder(new JacksonDecoder())
//				.options(new Request.Options(3L, TimeUnit.SECONDS, 5L, TimeUnit.SECONDS, true))
//				.target(L1RpcService.class, "http://192.168.0.176:2789");
//		L1RpcResponse l1RpcResponse = l1RpcService.maxeRegistL1(L1RpcParams.registerL1Params(3328, "0x74A2AD6bdCF2fD7075f22cDE7c3e86a70f3B9fF2"));
//		System.out.println("---------");
//	}
//
//	@Test
//	public void getL1TxHash() throws IOException {
//		//第一个是TxState合约地址，第二个是from
//		List<Type> result = ethUtils.ethCall("0x0a030d4d1af7803c33e859ccd59af2a7aa1c15d1", "getL1Txhash", Arrays.asList(new Address("0xEF304700DdA9A0E41a4299e55a97857773b6fbef"), new Uint64(2)), List.of(new TypeReference<DynamicBytes>() {
//		}));
//		System.out.println(Numeric.toHexString(((DynamicBytes) result.get(0)).getValue()));
//	}
//
//	@Test
//	public void testWebAuthnCredentialsRepository() throws IOException {
////		credentialService.deleteCredential(293L, "pQECAyYgASFYIFEjVfNtzqV64adnfz54p0sAnJI+SoLnh6b9s6r2i1FzIlggF8ONyqCMpfc2s6Imt6dFhana05lNMCvO7e1WMf1LP8A=");
//		List<JpaWebAuthnCredentials> collect = credentialsRepository.findAllByAppUserId(293L).stream().filter((JpaWebAuthnCredentials credential) -> credential.getCredentialId() == null).collect(Collectors.toList());
////		System.out.println(Base64.getEncoder().encodeToString(collect.get(0).getPublicKeyCose()));
//	}

}
