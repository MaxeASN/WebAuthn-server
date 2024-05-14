// const SERVER = "https://aspark.space";
const SERVER = "http://localhost:58080";
const GET_TRANSACTION_HISTORY = SERVER + "/api/transaction/list";
const GET_L1ADDRESS = SERVER + "/api/l1/list";
const ADD_L1ADDRESS = SERVER + "/api/l1/add";

const web3 = new Web3('https://aspark.space/rpc');
const web3_goerli_eth = new Web3('https://eth-goerli.g.alchemy.com/v2/bJYn-QJsqyOZINN6FFXo162x6stKh8He');