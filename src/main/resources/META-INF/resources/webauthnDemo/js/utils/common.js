function formatBalance(balance){
    let strNum = balance.toString(); // 将num转换为字符串
    let index = strNum.indexOf('.');
    if (strNum.substring(index+1) > 4) {
        let result = strNum.slice(0, index + 5); // 截取小数点前4位和小数点后一位

// 判断小数的第三位和第四位是否为0
        if (strNum.charAt(index + 3) === '0' && strNum.charAt(index + 4) === '0') {
            result = strNum.slice(0, index + 3); // 取小数点前两位和小数点后一位
        }
        //判断小数是否只有第四位为0
        if (strNum.charAt(index + 3) !== '0' && strNum.charAt(index + 4) === '0') {
            result = strNum.slice(0, index + 4); // 取小数点前两位和小数点后一位
        }
        return result;
    }
    return balance;
}