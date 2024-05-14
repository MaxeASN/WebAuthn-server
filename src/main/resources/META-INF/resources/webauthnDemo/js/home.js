//createTransferButton
let ethCoin = document.querySelector("#pane-token > div:nth-child(1)");
let usdtCoin = document.querySelector("#pane-token > div:nth-child(2)");
let usdcCoin = document.querySelector("#pane-token > div:nth-child(3)")
ethCoin.addEventListener('click', event => {
    if (!event.target.closest('button.up-button')){
        let targetNode = ethCoin.querySelector(".bottom");
        if(targetNode === null){
            const newDiv = document.createElement("div");
            newDiv.classList.add("bottom");
            newDiv.innerHTML = `
        <button class="el-button el-button--primary up-button" aria-disabled="false" type="button" onclick="window.location.href='/send?symbol=ETH&chain=eth'"><!--v-if-->
            <span class="">SEND</span>
        </button>
    `;
            ethCoin.appendChild(newDiv)
        }else{
            ethCoin.removeChild(targetNode);
        }
    }

})

usdtCoin.addEventListener('click', event => {
    if (!event.target.closest('button.up-button')){
        let targetNode = usdtCoin.querySelector(".bottom");
        if(targetNode === null){
            const newDiv = document.createElement("div");
            newDiv.classList.add("bottom");
            newDiv.innerHTML = `
            <button class="el-button el-button--primary up-button" aria-disabled="false" type="button" onclick="window.location.href='/send?symbol=USDT&chain=eth'"><!--v-if-->
                <span class="">SEND</span>
            </button>
        `;
            usdtCoin.appendChild(newDiv)
        }else{
            usdtCoin.removeChild(targetNode);
        }
    }
})
usdcCoin.addEventListener('click', event => {
    if (!event.target.closest('button.up-button')){
        let targetNode = usdcCoin.querySelector(".bottom");
        if(targetNode === null){
            const newDiv = document.createElement("div");
            newDiv.classList.add("bottom");
            newDiv.innerHTML = `
            <button class="el-button el-button--primary up-button" aria-disabled="false" type="button" onclick="window.location.href='/send?symbol=USDC&chain=eth'"><!--v-if-->
                <span class="">SEND</span>
            </button>
        `;
            usdcCoin.appendChild(newDiv)
        }else{
            usdcCoin.removeChild(targetNode);
        }
    }
})

//convertTab
let tokenTab = document.getElementById("tab-token");
let transactionRecordTab = document.getElementById("tab-collection");
let activeBar = document.querySelector('.el-tabs__active-bar.is-top');
let tokenPane = document.getElementById("pane-token");
let transactionRecordPane = document.getElementById("pane-collection");
let intervalId;
transactionRecordTab.addEventListener('click', function (){
    tokenTab.className = "el-tabs__item is-top";
    transactionRecordTab.classList.add("is-active");
    activeBar.style.width = '70px';
    activeBar.style.transform = 'translateX(132px)';
    transactionRecordPane.setAttribute("aria-hidden", "false");
    transactionRecordPane.setAttribute("style", "overflow-y: auto; height: 300px;");
    tokenPane.setAttribute("aria-hidden", "true");
    tokenPane.setAttribute("style", "display: none; ");
    displayTransactionHistory();
    // 设置定时事件，并保存ID
    intervalId = setInterval(() => {
        displayTransactionHistory();
    }, 10000);
})

tokenTab.addEventListener('click', function (){
    transactionRecordTab.className = "el-tabs__item is-top";
    tokenTab.classList.add("is-active");
    activeBar.style.width = '70px';
    activeBar.style.transform = 'translateX(0px)';
    tokenPane.setAttribute("aria-hidden", "false");
    tokenPane.setAttribute("style", "");
    transactionRecordPane.setAttribute("aria-hidden", "true");
    transactionRecordPane.setAttribute("style", "display: none;");
    // 取消查询交易的定时事件
    clearInterval(intervalId);
})

//displayBalance
let address = document.querySelector("#display-address > span").innerText;
const username = document.getElementById("display-username").innerText;
let web3_l1 = web3_goerli_eth;
Cookies.set("username", username, { expires: 36500 })
function displaySelectAddress(){
    if(address && username){
        let displayAddress;
        if(Cookies.get(username+"_select_address")){
            displayAddress = Cookies.get(username+"_select_address");
        }else{
            displayAddress = address;
            Cookies.set(username+"_select_address", address, { expires: 36500 })
        }
        displayAddress = displayAddress.substring(0, 6) + '...' + displayAddress.substring(37);
        document.querySelector("#display-address > span").innerText = displayAddress;
    }
}
displaySelectAddress()
if(address){
    getAndUpdateLayer2Balance();
    setInterval(() => {
        getAndUpdateLayer2Balance();
    }, 10000); //10秒刷新一次余额

}

if(address && username){
    getAndUpdateLayer1Balance();
    setInterval(() => {
        getAndUpdateLayer1Balance();
    }, 10000); //10秒刷新一次余额
}

async function getAndUpdateLayer1Balance() {
    let selectAddress = Cookies.get(username+"_select_address") || address;
    web3_l1.eth.getBalance(selectAddress, (err, balance) => {
        if (err) {
            console.error(err);
            return;
        }
        balance = web3.utils.fromWei(balance, 'ether');
        updateLayer1EthBalance(balance);
    });
}

function updateLayer1EthBalance(balance) {
    let result = formatBalance(balance);
    let ethAmount = document.querySelector("#token-box-balance-eth > div:nth-child(2)");
    ethAmount.innerText = result;
}

async function getAndUpdateLayer2Balance(){
    web3.eth.getBalance(address, (err, balance) => {
        if (err) {
            console.error(err);
            return;
        }
        balance = web3.utils.fromWei(balance, 'ether');
        updateLayer2EthBalance(balance);
    });
}

function updateLayer2EthBalance(balance){
    let result = formatBalance(balance);
    let ethAmount = document.getElementById("mainCoin_amount");
    ethAmount.innerText = result;
}

//displayTransactionHistory
function displayTransactionHistory(){
    fetch(GET_TRANSACTION_HISTORY)
        .then(response=> response.json())
        .then(({ code: c, message: m, data: d }) => [c, m, d])
        .then(([code, message, data]) => {
            if(code != 1) throw new Error(message);
            const transactionList = data.list;
            if(transactionList.length > 0){
                let transactionHtml = "";
                for (let i = 0; i<transactionList.length; i++){
                    let dateStr = formatDate(transactionList[i].createTime);
                    let amount = transactionList[i].amount;
                    let chainId = transactionList[i].chainId;
                    let displayAddress = transactionList[i].toAddress.substring(0, 6) + '...' + transactionList[i].toAddress.substring(37);
                    transactionHtml = transactionHtml + `<div class="coin" "><div class="top"><div class="up-token index"><div class="token-box"><svg width="36" height="36" viewBox="0 0 30 30" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="0.5" y="0.5" width="29" height="29" rx="14.5" stroke="#0376c9"></rect><path d="M18.5851 9.88921C18.5586 9.89005 18.5321 9.89238 18.5057 9.89618H14.3207C14.0635 9.89254 13.8243 10.0276 13.6947 10.2497C13.565 10.4719 13.565 10.7466 13.6947 10.9687C13.8243 11.1908 14.0635 11.3259 14.3207 11.3222H16.8777L9.53811 18.6614C9.35182 18.8402 9.27679 19.1058 9.34193 19.3557C9.40707 19.6056 9.60222 19.8007 9.85211 19.8658C10.102 19.931 10.3676 19.8559 10.5464 19.6697L17.886 12.3305V14.8874C17.8823 15.1445 18.0175 15.3837 18.2396 15.5133C18.4617 15.643 18.7364 15.643 18.9585 15.5133C19.1806 15.3837 19.3158 15.1445 19.3121 14.8874V10.6997C19.3409 10.4919 19.2767 10.282 19.1366 10.1259C18.9965 9.96973 18.7948 9.88316 18.5851 9.88921Z" fill="#0376c9"></path></svg></div><div class="index"><div class="index-title">发送</div><div class="index-subtitle"><span style="color:#28a745;">${dateStr}</span>
                                                        至：${displayAddress}</div></div></div><div class="balance"><iconpark-icon icon-id="loading" class="iconpark icon-loading is-loading duration" style="display: none;" name="" size="1em" width="" height=""></iconpark-icon><div>-${amount} ETH</div><div class="up-dollar" symbol="ETH">chain ${chainId}</div></div></div></div>`;
                }
                let nftNoneDiv = document.querySelector(".nft-none");
                nftNoneDiv.setAttribute("style", "display: none;");
                let paneCollectionDiv = document.getElementById("pane-collection")
                paneCollectionDiv.querySelectorAll(".coin").forEach(node => paneCollectionDiv.removeChild(node));
                nftNoneDiv.insertAdjacentHTML('afterend',transactionHtml);
            }
        })
        .catch(error => console.error(error));
}

function formatDate(dateString) {
    const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

    const date = new Date(dateString);
    const month = months[date.getMonth()];
    const day = date.getDate();

    return `${month} ${day} ·`;
}

//获取用户地址列表并显示
let addressOptionDiv = document.querySelector(".chain-select-container.address-options");
async function displayL1Address() {
    if (addressOptionDiv.style.display === "none") {
        await updateL1Address();
        //取消显示主网选择
        let setIcon = document.querySelector(".setting-icons");
        if (setIcon.getAttribute("data-display") === "true") {
            await showCoinMenu();
        }

        document.querySelector(".up-home-page-header").classList.add("up-home-page-header-bg");
        addressOptionDiv.style.display = "";
        document.getElementById("cover-address-select").style.display = "";
    }else{
        document.querySelector(".up-home-page-header").classList.remove("up-home-page-header-bg");
        addressOptionDiv.style.display = "none"
        document.getElementById("cover-address-select").style.display = "none";
    }
}

async function updateL1Address(){
    if(username === "" || address==="") return;
    let selectAddress = Cookies.get(username+"_select_address") || address;
    await fetch(GET_L1ADDRESS)
        .then(response => response.json())
        .then(({code: c, message: m, data: d}) => [c, m, d])
        .then(([code, message, data]) => {
            if (code != 1) throw new Error(message);
            if (data.length > 0) {
                // 获取父元素和按钮元素
                let parentDiv = document.querySelector(".chain-select-options.chain-options");
                let buttonDiv = parentDiv.querySelector(".button-box.button-box-padding");
                let previousAddressList = parentDiv.querySelectorAll(".option");
                for (let i=0;i<previousAddressList.length;i++){
                    parentDiv.removeChild(previousAddressList[i]);
                }
                for (let i = 0; i < data.length; i++) {
                    let optionDiv = document.createElement("div");
                    optionDiv.className = "option";
                    let labelDiv = document.createElement("div")
                    labelDiv.className = "label";
                    labelDiv.innerText = data[i];
                    optionDiv.appendChild(labelDiv);
                    optionDiv.addEventListener("click", updateDisplayAddress);
                    if(data[i] === selectAddress){
                        labelDiv.insertAdjacentHTML("afterend", `<iconpark-icon icon-id="round-select" class="iconpark icon-round-select round-select" name="" size="1em" width="" height=""></iconpark-icon>`);
                    }else{
                        labelDiv.insertAdjacentHTML("afterend", `<img src="img/delete.svg" style="margin-left: auto">`);
                    }
                    parentDiv.insertBefore(optionDiv, buttonDiv);
                }
            }
        })
        .catch(error => console.error("查询l1地址失败:" + error));
}

function updateDisplayAddress(event) {
    const selectAddress = event.currentTarget.querySelector(".label").innerText;
    Cookies.set(username + "_select_address", selectAddress, {expires: 36500});
    displayL1Address();
    displaySelectAddress();
    getAndUpdateLayer1Balance();
}

function displayCreateAddressConfirm(){
    let confirmDiv = document.getElementById("create-address-confirm");
    confirmDiv.style.display = "";
}

function hideCreateAddressConfirm(){
    let confirmDiv = document.getElementById("create-address-confirm");
    confirmDiv.style.display = "none";
}

function createL1Address(){
    fetch(ADD_L1ADDRESS)
        .then(response=> response.json())
        .then(({ code: c, message: m, data: d }) => [c, m, d])
        .then(([code, message, data]) => {
            if(code != 1) {
                alert(message);
                throw new Error(message);
            }
            alert("创建成功");
            hideCreateAddressConfirm();
            updateL1Address();
        })
        .catch(error => console.error(error));

}

function closeTransactionDetails(){
    let transactionOverlay = document.querySelector(".el-overlay.transaction-details");
    transactionOverlay.style.display = "none";
}

let fidoPbKey = document.getElementById("fidoid").innerText;
function displayFidoPbKey() {
    let displayFidoPbKey = fidoPbKey;
    if (displayFidoPbKey.length > 30){
        displayFidoPbKey = displayFidoPbKey.substring(0, 16) + "......" + displayFidoPbKey.substring(displayFidoPbKey.length - 15);
    }
    document.getElementById("fidoid").innerText = displayFidoPbKey;
}
displayFidoPbKey();
