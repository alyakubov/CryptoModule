package main

import (
	"fmt"
	"log"
        "io/ioutil"
        "os"
        "time"
	"math"
	"math/big"
	"strings"
         //"flag"
        "net/http"
        "encoding/hex"
        "crypto/rand"
        "crypto/rsa"
        "crypto/sha256"
        "encoding/gob"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"

	"github.com/buger/jsonparser"
)

const gKey = `{"address":"7b41bc79ca4d9bc12fb65d1f5d7f39418c03bc77","crypto":{"cipher":"aes-128-ctr","ciphertext":"5c385f8b1153c8d09b7032e2a09d02134f0e1f109747d85641c417584d399c88","cipherparams":{"iv":"a2d5f0de312656f47a58045e6df19ef5"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"be4f9268570504758907a0bc61ccbcdcfe7f2bf83f659c820e82186a0939c4a8"},"mac":"610e8b6b3d2d6ec9acdacb4202aa6f405033da13e83d51eab7765215a2ad51bd"},"id":"3a5e6f54-c16d-4d3e-84bf-9a5558598b15","version":3}`

const gAddrCryptoModule = "0xc353c3c46aac1626486df3223c06a925add7e122";

var gSession *CryptoModuleSession;
var gPublicKey rsa.PublicKey;


func main() {

    err := LoadPubKey(&gPublicKey)
    if err != nil {
        log.Fatalf("Cannot open public key file : %v", err)
        return;
    }

    // Create an IPC based RPC connection to a remote node
    conn, err := rpc.NewIPCClient("/home/alex/_Work/Eth_AeroNet_t/geth.ipc")
    if err != nil {
        log.Fatalf("Failed to connect to the Ethereum client: %v", err)
        return;
    }
    // Instantiate the contract, the address is taken from eth at the moment of contract initiation
    ethCrypto, err := NewCryptoModule(common.HexToAddress(gAddrCryptoModule), backends.NewRPCBackend(conn))
    if err != nil {
        log.Fatalf("Failed to instantiate a CryptoModule contract: %v", err)
        return;
    }

    // Logging into Ethereum as a user
    auth, err := bind.NewTransactor(strings.NewReader(gKey), "ira")
    if err != nil {
        log.Fatalf("Failed to create authorized transactor: %v", err)
        return;
    }

    // Session origination with reserved Ethers
    gSession := &CryptoModuleSession{
        Contract: ethCrypto,
        CallOpts: bind.CallOpts{
            Pending: true,
        },
        TransactOpts: bind.TransactOpts{
            From:     auth.From,
            Signer:   auth.Signer,
        },
    }
    gSession.TransactOpts = *auth;
    gSession.TransactOpts.GasLimit = big.NewInt(2000000)    

    doneReqInd := make( map[int64]bool );
    numRD, err := gSession.NumRegData()
    if err != nil {
        log.Fatalf("Failed to retrieve a total number of data records: %v", err)
    }
    for i := int64(0); i < numRD.Int64(); i++ {
        bi := big.NewInt(i)

        delRegDatum, err := gSession.DeletedRegData( bi)
        if err != nil {
            log.Fatalf("Deletion retrieval error: %v", err)
        }

        if delRegDatum.DeletionDate.Int64() != 0 {
            doneReqInd[i] = true;
        }
    }

    for bigIndex := int64(1); true; bigIndex++ {
        buff, err := CallRPC(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":100}`)
        if err != nil {
            log.Fatalf("Failed to call for recent bock Num: %v", err)
        }
        blockNumStr, err := jsonparser.GetString( buff, "result" )
        if err != nil {
            log.Fatalf("Failed to parse JSON response for a BlockNum: %v", err)
        }
        blockNumStr = strings.Replace( blockNumStr, "0x", "", 1)
        blockNumArr, err := hex.DecodeString( blockNumStr );
        if err != nil {
            log.Fatalf("Failed to hex-decode data: %v", err)
        }
        
        blockNum, _ := hexArrValue( blockNumArr, false )
        if ( blockNum > 2 ) {
            blockNum = blockNum - 2;
        }

        buff, err = CallRPC(`{"jsonrpc":"2.0","method":"eth_newFilter","params":[{"address": "` + gAddrCryptoModule +`", "topics":["0xfe6c85cc99f647d8b97352606d3d70643197c439a2f82e8b533a55b85906f56c"], "fromBlock":"` + fmt.Sprintf("0x%x", blockNum) + `","toBlock":"latest"}],"id":` + fmt.Sprintf("%d", 100+bigIndex)+`}`)
        log.Print(string(buff))
        if err != nil {
            log.Fatalf("Failed to call for newFilter: %v", err)
        }

        //{"jsonrpc":"2.0","id":31,"result":"0x634ff751e0ee8931b295546c8bda7f9e"}
        //respId, _ := jsonparser.GetInt( buff, "id" )
        hashFilter, ferr := jsonparser.GetString( buff, "result" )
        if ferr != nil {
            log.Fatalf("Failed to parse JSON response for newFilter: %v", ferr)
        }
        log.Print(hashFilter)
    
        for smallIndex := 1; smallIndex <= 20; smallIndex++ {
            time.Sleep(10*time.Second)

            buff, err := CallRPC(`{"jsonrpc":"2.0","method":"eth_getFilterLogs","params":["`+hashFilter+`"],"id":`+ fmt.Sprintf("%d", smallIndex)+`}`);
            if err != nil {
                log.Fatalf("Failed to call GetFilterINFO: %v", err)
            }
            //fmt.Print(string(buff))
            fmt.Print(".")

            //respId, _ = jsonparser.GetInt( buff, "id" )
            var strData []string;
            jsonparser.ArrayEach( buff, 
                func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
                    str, err := jsonparser.GetString(value, "data")
                    if err != nil {
                        log.Fatalf("Failed to get string data: %v", err)
                    }
                    //log.Print(str)
                    strData = append( strData, str )
                }, "result")

            if( len(strData) == 0) {
               continue;
               //break;
            }    

            for iStrData:=len(strData)-1; iStrData>=0; iStrData=iStrData-1 {
                tStr := strings.Replace(strData[iStrData], "0x", "", 1)
                bData, berr := hex.DecodeString(tStr);
                if berr != nil {
                    log.Fatalf("Failed to hex-decode data: %v", berr)
                }
    
                reqInd, _ := hexArrValue( bData[:32], false )
                done, _ := doneReqInd[int64(reqInd)]
                if (done == true) {
                    continue;
                } 

                offset, _ := hexArrValue( bData[32:64], true )
                if (offset != 64) {
                   log.Fatalf("Offset in request is not 64 : %v", reqInd);
                   return;
                }

                reqDataLen, err := hexArrValue( bData[64:96], true )
                if (err != nil) {
                    log.Fatalf("Data array length check : %v", err);
                    return;
                }
                //log.Printf("Request data len = %v", reqDataLen);

                reqData := bData[96:96+reqDataLen];
                //log.Print( string(reqData) );

                encrData, err := Encrypt(reqData, &gPublicKey)
                if (err != nil) {
                   log.Fatalf("Data array length check : %v", err);
                   return;
                }
                fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(reqData), encrData)

                tx, err := gSession.EncryptResponse(big.NewInt(int64(reqInd)), encrData)
                if err != nil {
                   log.Fatalf("Failed to add a record to blockchain: %v", err)
                }
                fmt.Printf("Pending encrypt response: 0x%x\n", tx.Hash())
                doneReqInd[int64(reqInd)] = true;
            }
        }

        buff, err = CallRPC(`{"jsonrpc":"2.0","method":"eth_uninstallFilter","params":["`+hashFilter+`"],"id":`+ fmt.Sprintf("%d", bigIndex) +`}`)
        if err != nil {
            log.Fatalf("Failed to receive response for UninstallFilter: %v", err)
        }

        uninst, _, _, ferr := jsonparser.Get( buff, "result" )
        if ferr != nil {
            log.Fatalf("Failed to parse Json for UninstallFilter: %v", ferr)
        }
        if string(uninst) == "true" {
            fmt.Println("1")
        } else {
            fmt.Println("0")
        }
    }
}


func CallRPC(query string) ([]byte, error) {
    body := strings.NewReader(query)
    req, err := http.NewRequest("POST", "http://127.0.0.1:8084", body)
    if err != nil {
        return nil, err;
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err;
    }
    defer resp.Body.Close()
    return ioutil.ReadAll(resp.Body)
}

func LoadPubKey(publicKey *rsa.PublicKey) (error) {
      publickeyfile, err := os.Open("a_pb.key")
      if err != nil {
          return err;
      }
      defer publickeyfile.Close()

      decoder := gob.NewDecoder(publickeyfile)
      err = decoder.Decode(publicKey)
      if err != nil {
          return err;
      }
      fmt.Println("Public key loaded")
      return nil;
}

func Encrypt(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {
      label := []byte("")  
      hash := sha256.New()

      return rsa.EncryptOAEP(hash, rand.Reader, publicKey, msg, label)
}

func hexArrValue( arr []byte, lenCheck bool ) (int, error) {
    var currVal int = 0;
    for  i:=1; i<=len(arr); i++  {
        if( arr[len(arr)-i] == 0 ) {
            return currVal, nil;
        } else {
            currVal = currVal + int(arr[len(arr)-i]) * int( math.Pow( 256,float64(i-1) ) );
            if (lenCheck == true) && (i>2) {
                err := HexConvError{"Hex to int conversion: value is too big"};
                return currVal, err;
            }
        }
    }
    return currVal, nil
}

type HexConvError struct {
   errMsg string;
}
func (e HexConvError) Error() string {
    return e.errMsg
}



