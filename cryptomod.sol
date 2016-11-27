pragma solidity ^0.4.0;

contract LUCrypProxy {
    function encryptCallBack(uint _cryptoID, bytes _bData);
}

contract LUCrypModule {

    address public founder;
    uint public numRegData;
    RegDatum[] public regData;
    mapping (uint => DeletedRegDatum) public deletedRegData;

    string[] public errLog;
    uint public errLogNum;

    event evSendData(uint ind, bytes _bData);
        
    struct RegDatum {
        address nodeSender;
        bytes bData;
        string descript;
        uint creationDate;
    }

    struct DeletedRegDatum {
        address nodeSender;
        uint deletionDate;
    }

    function LUCrypModule() {
        founder = msg.sender;  
    }

    function encryptRequest(bytes _data) returns (uint _regID) {
        _regID = regData.length++;
        RegDatum reg = regData[_regID];
        reg.nodeSender = msg.sender;
        reg.creationDate = now;
        reg.bData = _data;
        reg.descript = "";

        numRegData = _regID + 1;
        evSendData(_regID, _data);
    }

    function encryptResponse(uint _regID, bytes _data) returns (uint err) {
        uint _err = deleteRegDatum(_regID);
        if (_err == 1) {
            logError("Error: the message num excceds the available scope");
            return _err;
        }
        if (_err == 2) {
            logError("Error: the message was already send (response was returned)");
            return _err;
        }
        LUCrypProxy theContr = LUCrypProxy(regData[_regID].nodeSender);
        theContr.encryptCallBack(_regID, _data);
    }

    function deleteRegDatum(uint _regID) internal returns (uint err) {
        if (_regID >= numRegData) {
           return 1;
        }
        if (deletedRegData[_regID].deletionDate != 0) {
           return 2;
        }
        deletedRegData[_regID] = DeletedRegDatum(msg.sender, now);
        return 0;
    }

    function logError(string _sError) internal returns (uint _logID) {
        _logID = errLog.length++;
        /*_dateStr = string(now);*/
        errLog[_logID] = _sError;

        errLogNum = _logID+1;
    }
}

