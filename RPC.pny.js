var exec=require(__dirname+'/../node_modules/shelljs.exec');
var RPC=module.exports={
    daemon:' PNY.cli -datadir="/home/PNY/data"'
,   exec:function(cmd){
        var x=exec(cmd,{silent:true});
        return {e:x.stderr,r:x.stdout};
        }
,   mode:'real'
,   test:function(method,multiple){
        var o;
        if(multiple){o=RPC.exec(multiple);}
        else{o=RPC.exec(RPC.daemon+' help '+method);}
        method='/home/'+RPC.dir+'/test-binaries/'+method+'.help';
        if(fs.existsSync(method)==false){
            fs.writeFileSync(method,o.r,'utf-8');
            }
        if(o.r!==fs.readFileSync(method,'utf-8')){
            if(!o.e){fs.writeFileSync(method,o.r,'utf-8');}
            o.r='help file differs';
            }
        else{
            o.r={};
            }
        return o;
        }
,   dir:'PNY'
,   getchaintiplag:function(confirmations,blockhash,tipblock,callback){
        var audit=[];
        var lag=-1;
        var confs=confirmations-(confirmations*2);//negative number
        function correct_chain(c,b,tip,cb){
            correct_chain=undefined;
            b=RPC.getblock(b);
            if(!b.e&&b.r&&b.r.confirmations>0&&!tip.e&&tip.r&&tip.r.confirmations>0){
                b=b.r;
                tip=tip.r;
                (function ___fwd(c,n,y,z){
                    if(c>1){
                        y=n;
                        z=RPC.getblock(n.prev);
                        if(lag==-1&&typeof n=='object'&&n.hash==b.hash&&JSON.stringify(n.tx)==JSON.stringify(b.tx)){
                            lag=confirmations-c;
                            }
                        if(z.r&&z.r.prev&&z.r.confirmations>0){
                            setTimeout(___fwd,0,c-1,z.r,y,undefined);
                            }
                        else if(lag>-1){
                            cb('FOUNDBLOCKNOTIP',false,lag);//found the block but not the tip
                            }
                        else{
                            cb('WRONGCHAIN',false,lag);//wrong chain
                            }
                        }
                    else{//end
                        if(lag==-1&&typeof n=='object'&&n.hash==b.hash&&JSON.stringify(n.tx)==JSON.stringify(b.tx)){
                            lag=confirmations-c;
                            cb('OK',true,lag);
                            }
                        else{
                            cb('NOTIP',false,lag);
                            }
                        }
                    })(c,tip);//confs,tip
                }
            else{
                cb('FAILBEFORE',false,lag);
                }
            }
        correct_chain(confirmations,blockhash,tipblock,function(lable,trusted,lag){
            callback(lable,trusted,lag);
            });
        }
,   getprogress:function(){
        var p=RPC.exec('grep "progress=" /home/'+RPC.dir+'/data/debug.log | tail -1');
        if(p.e||!p.r){
            return 0.0;
            }
        else{//1 or higher for at tip or something like 9.999968 for behind
            p=p.r.split('progress=')[1];
            p=p.split(' ')[0];
            return p;
            }
        }
,   signmessage:function(addr,msg,pw,keepopen){
        /*
        signmessage "PNYaddress" "message"

        Sign a message with the private key of an address

        Arguments:
        1. "PNYaddress"  (string, required) The PNY address to use for the private key.
        2. "message"         (string, required) The message to create a signature of.

        Result:
        "signature"          (string) The signature of the message encoded in base 64

        Examples:

        Unlock the wallet for 30 seconds
        > peony-cli walletpassphrase "mypassphrase" 30

        Create the signature
        > peony-cli signmessage "DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6" "my message"

        Verify the signature
        > peony-cli verifymessage "DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6" "signature" "my message"

        As json rpc
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signmessage", "params": ["DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6", "my message"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        RPC.walletpassphrase(pw);
        var o=RPC.exec(RPC.daemon+' signmessage "'+addr+'" "'+msg+'"');
        o.r=o.r==''?undefined:(o.r.replace('\n',''));
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(!keepopen){RPC.walletlock();}
        if(RPC.mode=='test'){o.t=RPC.test('signmessage');}
        return o;
        }
,   gettransaction:function(txid){
        /*
        gettransaction "txid" ( includeWatchonly )

        Get detailed information about in-wallet transaction <txid>

        Arguments:
        1. "txid"    (string, required) The transaction id
        2. "includeWatchonly"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]

        Result:
        {
          "amount" : x.xxx,        (numeric) The transaction amount in PNY
          "confirmations" : n,     (numeric) The number of confirmations
          "bcconfirmations" : n,   (numeric) The number of blockchain confirmations
          "blockhash" : "hash",  (string) The block hash
          "blockindex" : xx,       (numeric) The block index
          "blocktime" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)
          "txid" : "transactionid",   (string) The transaction id.
          "time" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)
          "timereceived" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)
          "details" : [
            {
              "account" : "accountname",  (string) DEPRECATED.This field will be removed in v5.0. To see this deprecated field, start peonyd with -deprecatedrpc=accounts. The account name involved in the transaction, can be "" for the default account.
              "address" : "PNYaddress",   (string) The PNY address involved in the transaction
              "category" : "send|receive",    (string) The category, either 'send' or 'receive'
              "amount" : x.xxx                  (numeric) The amount in PNY
              "vout" : n,                       (numeric) the vout value
            }
            ,...
          ],
          "hex" : "data"         (string) Raw data for transaction
        }

        Examples:
        > peony-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
        > peony-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" true
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettransaction", "params": ["1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if(txid!==undefined){//maybe skipped during test
            o=RPC.exec(RPC.daemon+' gettransaction "'+txid+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                var found_generated=o.r.indexOf('generated')!==-1;//found? true
                try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
                if(o.r.generated==undefined&&found_generated==true){
                    o.r.problem_tx=JSON.stringify(JSON.parse(o.r));
                    o.r.problem_tx.problem='This tx has generated written somewhere none standard!';
                    }
                found_generated=undefined;
                }
            if(typeof o.r=='object'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:{
                        txid:                   o.r.txid==undefined?'missing':o.r.txid//string
                    ,   block:                  o.r.blockhash==undefined?'block-not-found':o.r.blockhash//string
                    ,   amount:                 o.r.amount==undefined?'missing':o.r.amount//number
                    ,   fee:                    o.r.fee||undefined//number
                    ,   confirmations:          o.r.confirmations==undefined?'missing':o.r.confirmations//number
                    ,   details:                o.r.details//array
                    ,   generated:              o.r.generated||undefined//bool
                    ,   time:                   o.r.time==undefined?'missing':o.r.time//date number
                    ,   walletconflicts:        o.r.walletconflicts==undefined?'missing':o.r.walletconflicts//array?
                    ,   hex:                    o.r.hex==undefined?'missing':o.r.hex//string
                    ,   problem_tx:             o.r.problem_tx||undefined
                        }
                    };
                for(var i=0;i<o.r.details.length;i+=1){
                    o.r.details[i]={//object
                            address:            o.r.details[i].address==undefined?'can be blank':o.r.details[i].address//string
                        ,   category:           o.r.details[i].category==undefined?'missing':o.r.details[i].category//string
                        ,   amount:             o.r.details[i].amount==undefined?'missing':o.r.details[i].amount//number
                        ,   vout:               o.r.details[i].vout==undefined?'missing':o.r.details[i].vout//number
                            }
                    }
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected object, got '+(typeof o.r);}
            }
        if(RPC.mode=='test'){o.t=RPC.test('gettransaction');}
        return o;
        }
,   decoderawtransaction:function(hex,txid){
        /*
        decoderawtransaction "hexstring"

        Return a JSON object representing the serialized, hex-encoded transaction.

        Arguments:
        1. "hex"      (string, required) The transaction hex string

        Result:
        {
          "txid" : "id",        (string) The transaction id
          "size" : n,             (numeric) The transaction size
          "version" : n,          (numeric) The version
          "locktime" : ttt,       (numeric) The lock time
          "vin" : [               (array of json objects)
             {
               "txid": "id",    (string) The transaction id
               "vout": n,         (numeric) The output number
               "scriptSig": {     (json object) The script
                 "asm": "asm",  (string) asm
                 "hex": "hex"   (string) hex
               },
               "sequence": n     (numeric) The script sequence number
             }
             ,...
          ],
          "vout" : [             (array of json objects)
             {
               "value" : x.xxx,            (numeric) The value in PNY
               "n" : n,                    (numeric) index
               "scriptPubKey" : {          (json object)
                 "asm" : "asm",          (string) the asm
                 "hex" : "hex",          (string) the hex
                 "reqSigs" : n,            (numeric) The required sigs
                 "type" : "pubkeyhash",  (string) The type, eg 'pubkeyhash'
                 "addresses" : [           (json array of string)
                   "12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc"   (string) PNY address
                   ,...
                 ]
               }
             }
             ,...
          ],
        }

        Examples:
        > peony-cli decoderawtransaction "hexstring"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "decoderawtransaction", "params": ["hexstring"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if(hex!==undefined){//maybe skipped during test
            var file='/home/'+RPC.dir+'/'+(+new Date())+'.decoderawtransaction';
            fs.writeFileSync(file,hex,'utf-8');
            o=RPC.exec('DATA=$(cat '+file+'); '+RPC.daemon+' decoderawtransaction "\"${DATA}\""');
            fs.unlinkSync(file);
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
                }
            if(typeof o.r=='object'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:{
                        txid:                   o.r.txid==undefined?'missing':o.r.txid//string
                    ,   vin:                    o.r.vin
                    ,   vout:                   o.r.vout//array
                        }
                    };
                for(var i=0;i<o.r.vin.length;i+=1){
                    o.r.vin[i]={
                        txid:                   o.r.vin[i].txid==undefined?'missing':o.r.vin[i].txid//string
                    ,   vout:                   o.r.vin[i].vout==undefined?'missing':o.r.vin[i].vout//number
                        };
                    }
                for(var i=0;i<o.r.vout.length;i+=1){
                    o.r.vout[i]={
                        scriptPubKey:{
                            addresses:          o.r.vout[i].scriptPubKey.addresses==undefined?'can be blank':o.r.vout[i].scriptPubKey.addresses//array of strings
                            }
                    ,   n:                      o.r.vout[i].n==undefined?'missing':o.r.vout[i].n//number
                    ,   value:                  o.r.vout[i].value==undefined?'missing':o.r.vout[i].value//number
                        }
                    }
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected object, got '+(typeof o.r);}
            }
        if(RPC.mode=='test'){o.t=RPC.test('decoderawtransaction');}
        return o;
        }
,   gettxout:function(txid,vout,addr,pw){
        /*
        gettxout "txid" n ( includemempool )

        Returns details about an unspent transaction output.

        Arguments:
        1. "txid"       (string, required) The transaction id
        2. n              (numeric, required) vout value
        3. includemempool  (boolean, optional) Whether to included the mem pool

        Result:
        {
          "bestblock" : "hash",    (string) the block hash
          "confirmations" : n,       (numeric) The number of confirmations
          "value" : x.xxx,           (numeric) The transaction value in PNY
          "scriptPubKey" : {         (json object)
             "asm" : "code",       (string)
             "hex" : "hex",        (string)
             "reqSigs" : n,          (numeric) Number of required signatures
             "type" : "pubkeyhash", (string) The type, eg pubkeyhash
             "addresses" : [          (array of string) array of PNY addresses
             "PNYaddress"            (string) PNY address
                ,...
             ]
          },
          "coinbase" : true|false   (boolean) Coinbase or not
        }

        Examples:

        Get unspent transactions
        > peony-cli listunspent

        View the details
        > peony-cli gettxout "txid" 1

        As a json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettxout", "params": ["txid", 1] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if([txid,vout,addr].indexOf(undefined)==-1){//maybe skipped during test
            o=RPC.signmessage(addr,'x',pw);
            if(o.e){
                o={e:o.e,r:undefined};
                }
            else{
                o=RPC.exec(RPC.daemon+' gettxout "'+txid+'" '+vout);
                o.r=o.r==''?undefined:o.r;
                o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
                if(typeof o.r=='string'){
                    try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
                    }
                if(typeof o.r=='object'){
                    o={
                        e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                    ,   r:{
                            confirmations:          o.r.confirmations==undefined?'missing':o.r.confirmations//number
                        ,   value:                  o.r.value==undefined?'missing':o.r.value//float
                            }
                        };
                    if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                        o.f=true;
                        if(!o.e){o.e='some items are missing';}
                        }
                    }
                else{o.j='expected object, got '+(typeof o.r);}
                }
            }
        if(RPC.mode=='test'){o.t=RPC.test('gettxout');}
        return o;
        }
,   getblock:function(hash){
        /*
        getblock "hash" ( verbose )

        If verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'.
        If verbose is true, returns an Object with information about block <hash>.

        Arguments:
        1. "hash"          (string, required) The block hash
        2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data

        Result (for verbose = true):
        {
          "hash" : "hash",     (string) the block hash (same as provided)
          "confirmations" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain
          "size" : n,            (numeric) The block size
          "height" : n,          (numeric) The block height or index
          "version" : n,         (numeric) The block version
          "merkleroot" : "xxxx", (string) The merkle root
          "tx" : [               (array of string) The transaction ids
             "transactionid"     (string) The transaction id
             ,...
          ],
          "time" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
          "mediantime" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)
          "nonce" : n,           (numeric) The nonce
          "bits" : "1d00ffff", (string) The bits
          "difficulty" : x.xxx,  (numeric) The difficulty
          "previousblockhash" : "hash",  (string) The hash of the previous block
          "nextblockhash" : "hash"       (string) The hash of the next block
          "stakeModifier" : "xxx",       (string) Proof of Stake modifier
          "hashProofOfStake" : "hash",   (string) Proof of Stake hash
          }
        }

        Result (for verbose=false):
        "data"             (string) A string that is serialized, hex-encoded data for block 'hash'.

        Examples:
        > peony-cli getblock "00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblock", "params": ["00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.exec(RPC.daemon+' getblock "'+hash+'"');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.r=='string'){
            try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
            }
        if(typeof o.r=='object'){
            o={
                e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:{
                    confirmations:          o.r.confirmations==undefined?'missing':o.r.confirmations
                ,   height:                 o.r.height==undefined?'missing':o.r.height
                ,   hash:                   o.r.hash==undefined?'missing':o.r.hash
                ,   prev:                   o.r.previousblockhash==undefined?'missing':o.r.previousblockhash
                ,   tx:                     o.r.tx==undefined?'missing':o.r.tx//array of txids
                    }
                };
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('getblock');}
        return o;
        }
,   getchaintip:function(){
        /*
        getbestblockhash

        Returns the hash of the best (tip) block in the longest block chain.

        Result
        "hex"      (string) the block hash hex encoded

        Examples
        > peony-cli getbestblockhash
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getbestblockhash", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.exec(RPC.daemon+' getbestblockhash');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.r=='string'){
            o.r=o.r.replace('\n','');
            }
        else{o.j='expected string, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('getbestblockhash');}
        return o;
        }
,   getblockcount:function(){
        /*
        getblockcount

        Returns the number of blocks in the longest block chain.

        Result:
        n    (numeric) The current block count

        Examples:
        > peony-cli getblockcount
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockcount", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.exec(RPC.daemon+' getblockcount');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.r=='string'){
            try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
            }
        if(typeof o.r=='number'){
            o={
                e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:                          o.r==undefined?'missing':o.r
                };
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected number, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('getblockcount');}
        return o;
        }
,   walletlock:function(p){
        /*
        walletpassphrase "passphrase" timeout ( stakingonly )

        Stores the wallet decryption key in memory for 'timeout' seconds.
        This is needed prior to performing transactions related to private keys such as sending PNYs

        Arguments:
        1. "passphrase"     (string, required) The wallet passphrase
        2. timeout            (numeric, required) The time to keep the decryption key in seconds.
        3. stakingonly        (boolean, optional, default=false) If is true sending functions are disabled.
        Note:
        Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock
        time that overrides the old one. A timeout of "0" unlocks until the wallet is closed.

        Examples:

        Unlock the wallet for 60 seconds
        > peony-cli walletpassphrase "my pass phrase" 60

        Unlock the wallet for 60 seconds but allow staking only
        > peony-cli walletpassphrase "my pass phrase" 60 true

        Lock the wallet again (before 60 seconds)
        > peony-cli walletlock

        As json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "walletpassphrase", "params": ["my pass phrase", 60] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.exec(RPC.daemon+' walletpassphrase "'+p+'" 0 true');//this returns nothing?
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        o={
            e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
        ,   r:                          (o.e?false:true)
            };
        if(RPC.mode=='test'){o.t=RPC.test('walletlock',RPC.daemon+' help walletpassphrase');}
        return o;
        }
,   walletpassphrase:function(p){
        /*
        walletpassphrase "passphrase" timeout ( stakingonly )

        Stores the wallet decryption key in memory for 'timeout' seconds.
        This is needed prior to performing transactions related to private keys such as sending PNYs

        Arguments:
        1. "passphrase"     (string, required) The wallet passphrase
        2. timeout            (numeric, required) The time to keep the decryption key in seconds.
        3. stakingonly        (boolean, optional, default=false) If is true sending functions are disabled.
        Note:
        Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock
        time that overrides the old one. A timeout of "0" unlocks until the wallet is closed.

        Examples:

        Unlock the wallet for 60 seconds
        > peony-cli walletpassphrase "my pass phrase" 60

        Unlock the wallet for 60 seconds but allow staking only
        > peony-cli walletpassphrase "my pass phrase" 60 true

        Lock the wallet again (before 60 seconds)
        > peony-cli walletlock

        As json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "walletpassphrase", "params": ["my pass phrase", 60] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.exec(RPC.daemon+' walletpassphrase "'+p+'" 144000 false');//this returns nothing?
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        o={
            e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
        ,   r:                          (o.e?false:true)
            };
        if(RPC.mode=='test'){o.t=RPC.test('walletpassphrase');}
        return o;
        }
,   listunspent:function(address,min_confirmations){
        /*
        listunspent ( minconf maxconf  ["address",...] watchonlyconfig )

        Returns array of unspent transaction outputs
        with between minconf and maxconf (inclusive) confirmations.
        Optionally filter to only include txouts paid to specified addresses.
        Results are an array of Objects, each of which has:
        {txid, vout, scriptPubKey, amount, confirmations, spendable}

        Arguments:
        1. minconf          (numeric, optional, default=1) The minimum confirmations to filter
        2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter
        3. "addresses"    (string) A json array of PNY addresses to filter
            [
              "address"   (string) PNY address
              ,...
            ]
        4. watchonlyconfig  (numeric, optional, default=1) 1 = list regular unspent transactions,  2 = list all unspent transactions (including watchonly)

        Result
        [                   (array of json object)
          {
            "txid" : "txid",        (string) the transaction id
            "vout" : n,               (numeric) the vout value
            "address" : "address",  (string) the PNY address
            "label" : "label",      (string) The associated label, or "" for the default label
            "account" : "account",  (string) DEPRECATED.This field will be removed in v5.0. To see this deprecated field, start peonyd with -deprecatedrpc=accounts. Backwards compatible alias for label.
            "scriptPubKey" : "key", (string) the script key
            "redeemScript" : "key", (string) the redeemscript key
            "amount" : x.xxx,         (numeric) the transaction amount in PNY
            "confirmations" : n,      (numeric) The number of confirmations
            "spendable" : true|false  (boolean) Whether we have the private keys to spend this output
            "solvable" : xxx          (bool) Whether we know how to spend this output, ignoring the lack of keys
          }
          ,...
        ]

        Examples
        > peony-cli listunspent
        > peony-cli listunspent 6 9999999 "[\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\",\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\"]"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "listunspent", "params": [6, 9999999 "[\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\",\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\"]"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var f='/home/'+RPC.dir+'/'+(+new Date())+'.listunspent';
        var o;
        if(address!==undefined){
            o=RPC.exec(RPC.daemon+' listunspent '+min_confirmations+' 9999999 '+JSON.stringify(JSON.stringify([address]))+' > '+f+'; cat '+f);
            }
        else{
            o=RPC.exec(RPC.daemon+' listunspent > '+f+'; cat '+f);
            }
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        fs.unlinkSync(f);
        if(typeof o.r=='string'){
            try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
            }
        if(typeof o.r=='object'){
            o={
                e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:                          o.r||[]
                };
            for(var i=0,l=o.r.length;i<l;i+=1){
                o.r[i]={
                    txid:                   o.r[i].txid==undefined?'missing':o.r[i].txid
                ,   vout:                   o.r[i].vout==undefined?'missing':o.r[i].vout
                ,   address:                o.r[i].address==undefined?'missing':o.r[i].address
                ,   confirmations:          (address!==undefined?o.r[i].confirmations:undefined)
                ,   amount:                 o.r[i].amount==undefined?'missing':o.r[i].amount
                    };
                }
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('listunspent');}
        return o;
        }
,   createrawtransaction:function(inputs,outputs){
        /*
        createrawtransaction [{"txid":"id","vout":n},...] {"address":amount,...} ( locktime )

        Create a transaction spending the given inputs and sending to the given addresses.
        Returns hex-encoded raw transaction.
        Note that the transaction's inputs are not signed, and
        it is not stored in the wallet or transmitted to the network.

        Arguments:
        1. "transactions"        (string, required) A json array of json objects
             [
               {
                 "txid":"id",  (string, required) The transaction id
                 "vout":n,       (numeric, required) The output number
                 "sequence":n    (numeric, optional) The sequence number
               }
               ,...
             ]
        2. "addresses"           (string, required) a json object with addresses as keys and amounts as values
            {
              "address": x.xxx   (numeric, required) The key is the PNY address, the value is the PNY amount
              ,...
            }
        3. locktime                (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs

        Result:
        "transaction"            (string) hex string of the transaction

        Examples
        > peony-cli createrawtransaction "[{\"txid\":\"myid\",\"vout\":0}]" "{\"address\":0.01}"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "createrawtransaction", "params": ["[{\"txid\":\"myid\",\"vout\":0}]", "{\"address\":0.01}"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' createrawtransaction '+JSON.stringify(JSON.stringify(inputs))+' '+JSON.stringify(JSON.stringify(outputs)));
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                          o.r==undefined?'missing':o.r.replace('\n','')
                    };
                if(o.e){
                    o.f=' createrawtransaction '+JSON.stringify(JSON.stringify(inputs))+' '+JSON.stringify(JSON.stringify(outputs));
                    }
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected string, got '+(typeof o.r);}
            }
        if(RPC.mode=='test'){o.t=RPC.test('createrawtransaction');}
        return o;
        }
,   signrawtransaction:function(hex){
        /*
        signrawtransaction "hexstring" ( [{"txid":"id","vout":n,"scriptPubKey":"hex","redeemScript":"hex"},...] ["privatekey1",...] sighashtype )

        Sign inputs for raw transaction (serialized, hex-encoded).
        The second optional argument (may be null) is an array of previous transaction outputs that
        this transaction depends on but may not yet be in the block chain.
        The third optional argument (may be null) is an array of base58-encoded private
        keys that, if given, will be the only keys used to sign the transaction.

        Requires wallet passphrase to be set with walletpassphrase call.

        Arguments:
        1. "hexstring"     (string, required) The transaction hex string
        2. "prevtxs"       (string, optional) An json array of previous dependent transaction outputs
             [               (json array of json objects, or 'null' if none provided)
               {
                 "txid":"id",             (string, required) The transaction id
                 "vout":n,                  (numeric, required) The output number
                 "scriptPubKey": "hex",   (string, required) script key
                 "redeemScript": "hex"    (string, required for P2SH) redeem script
                 "amount": value            (numeric, required) The amount spent
               }
               ,...
            ]
        3. "privatekeys"     (string, optional) A json array of base58-encoded private keys for signing
            [                  (json array of strings, or 'null' if none provided)
              "privatekey"   (string) private key in base58-encoding
              ,...
            ]
        4. "sighashtype"     (string, optional, default=ALL) The signature hash type. Must be one of
               "ALL"
               "NONE"
               "SINGLE"
               "ALL|ANYONECANPAY"
               "NONE|ANYONECANPAY"
               "SINGLE|ANYONECANPAY"

        Result:
        {
          "hex" : "value",           (string) The hex-encoded raw transaction with signature(s)
          "complete" : true|false,   (boolean) If the transaction has a complete set of signatures
          "errors" : [                 (json array of objects) Script verification errors (if there are any)
            {
              "txid" : "hash",           (string) The hash of the referenced, previous transaction
              "vout" : n,                (numeric) The index of the output to spent and used as input
              "scriptSig" : "hex",       (string) The hex-encoded signature script
              "sequence" : n,            (numeric) Script sequence number
              "error" : "text"           (string) Verification or signing error related to the input
            }
            ,...
          ]
        }

        Examples:
        > peony-cli signrawtransaction "myhex"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signrawtransaction", "params": ["myhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' signrawtransaction "'+hex+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
                }
            if(typeof o.r=='object'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)||(o.r.errors||{}).error
                ,   r:  {
                        hex:                    o.r.hex==undefined?'missing':o.r.hex.replace('\n','')
                        }
                    };
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected object, got '+(typeof o.r);}
            }
        if(RPC.mode=='test'){o.t=RPC.test('signrawtransaction');}
        return o;
        }
,   sendrawtransaction:function(hex){
        /*
        sendrawtransaction "hexstring" ( allowhighfees )

        Submits raw transaction (serialized, hex-encoded) to local node and network.

        Also see createrawtransaction and signrawtransaction calls.

        Arguments:
        1. "hexstring"    (string, required) The hex string of the raw transaction)
        2. allowhighfees    (boolean, optional, default=false) Allow high fees

        Result:
        "hex"             (string) The transaction hash in hex

        Examples:

        Create a transaction
        > peony-cli createrawtransaction "[{\"txid\" : \"mytxid\",\"vout\":0}]" "{\"myaddress\":0.01}"
        Sign the transaction, and get back the hex
        > peony-cli signrawtransaction "myhex"

        Send the transaction (signed hex)
        > peony-cli sendrawtransaction "signedhex"

        As a json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "sendrawtransaction", "params": ["signedhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' sendrawtransaction "'+hex+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                          o.r==undefined?'missing':o.r.replace('\n','')
                    };
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected string, got '+(typeof o.r);}
            }
        if(RPC.mode=='test'){o.t=RPC.test('sendrawtransaction');}
        return o;
        }
,   lockunspent:function(unlock,txid,vout){
        /*
        lockunspent unlock [{"txid":"txid","vout":n},...]

        Updates list of temporarily unspendable outputs.
        Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.
        A locked transaction output will not be chosen by automatic coin selection, when spending PNYs.
        Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list
        is always cleared (by virtue of process exit) when a node stops or fails.
        Also see the listunspent call

        Arguments:
        1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions
        2. "transactions"  (string, required) A json array of objects. Each object the txid (string) vout (numeric)
             [           (json array of json objects)
               {
                 "txid":"id",    (string) The transaction id
                 "vout": n         (numeric) The output number
               }
               ,...
             ]

        Result:
        true|false    (boolean) Whether the command was successful or not

        Examples:

        List the unspent transactions
        > peony-cli listunspent

        Lock an unspent transaction
        > peony-cli lockunspent false "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

        List the locked transactions
        > peony-cli listlockunspent

        Unlock the transaction again
        > peony-cli lockunspent true "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

        As a json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "lockunspent", "params": [false, "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if([unlock,txid,vout].indexOf(undefined)==-1){//maybe skipped during test
            o=RPC.exec(RPC.daemon+' lockunspent '+unlock+' '+JSON.stringify(JSON.stringify([{txid:txid,vout:vout}])));//this is a bool not an object
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
                }
            if(typeof o.r=='boolean'){
                o={
                    e:                      (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                      o.r==undefined?'missing':o.r
                    };
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected boolean, got '+(typeof o.r);}
            }
        if(RPC.mode=='test'){o.t=RPC.test('lockunspent');}
        return o;
        }
,   estimatefee:function(blocks){
        /*
        getnetworkinfo

        Returns an object containing various state info regarding P2P networking.

        Result:
        {
          "version": xxxxx,                      (numeric) the server version
          "subversion": "/Peony:x.x.x.x/",     (string) the server subversion string
          "protocolversion": xxxxx,              (numeric) the protocol version
          "localservices": "xxxxxxxxxxxxxxxx", (string) the services we offer to the network
          "timeoffset": xxxxx,                   (numeric) the time offset
          "connections": xxxxx,                  (numeric) the number of connections
          "networks": [                          (array) information per network
          {
            "name": "xxx",                     (string) network (ipv4, ipv6 or onion)
            "limited": true|false,               (boolean) is the network limited using -onlynet?
            "reachable": true|false,             (boolean) is the network reachable?
            "proxy": "host:port"               (string) the proxy that is used for this network, or empty if none
          }
          ,...
          ],
          "relayfee": x.xxxxxxxx,                (numeric) minimum relay fee for non-free transactions in peony/kb
          "localaddresses": [                    (array) list of local addresses
          {
            "address": "xxxx",                 (string) network address
            "port": xxx,                         (numeric) network port
            "score": xxx                         (numeric) relative score
          }
          ,...
          ]
        }

        Examples:
        > peony-cli getnetworkinfo
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnetworkinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.exec(RPC.daemon+' getnetworkinfo');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.r=='string'){
            try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
            }
        if(typeof o.r=='object'){
            o={
                e:  (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:  o.r.relayfee!==undefined?o.r.relayfee:'missing'
                };
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(JSON.stringify(o).indexOf(':"missing"')!==-1){
            o.f=true;
            if(!o.e){o.e='some items are missing';}
            }
        if(RPC.mode=='test'){o.t=RPC.test('estimatefee',RPC.daemon+' help getnetworkinfo');}
        return o;
        }
,   validateaddress:function(address){
        /*
        validateaddress "PNYaddress"

        Return information about the given PNY address.

        Arguments:
        1. "PNYaddress"     (string, required) The PNY address to validate

        Result:
        {
          "isvalid" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.
          "type" : "xxxx",              (string) "standard"
          "address" : "PNY address",    (string) The PNY address validated
          "scriptPubKey" : "hex",       (string) The hex encoded scriptPubKey generated by the address -only if is standard address-
          "ismine" : true|false,          (boolean) If the address is yours or not
          "iswatchonly" : true|false,     (boolean) If the address is watchonly -only if standard address-
          "isscript" : true|false,        (boolean) If the key is a script -only if standard address-
          "hex" : "hex",                (string, optional) The redeemscript for the P2SH address -only if standard address-
          "pubkey" : "publickey hex",    (string) The hex value of the raw public key -only if standard address-
          "iscompressed" : true|false,    (boolean) If the address is compressed -only if standard address-
          ("pubkey" : "decompressed publickey hex",    (string) The hex value of the decompressed raw public key -only if standard address)-
          "account" : "account"         (string) DEPRECATED. The account associated with the address, "" is the default account
        }

        Examples:
        > peony-cli validateaddress "1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc"
        */
        var o=RPC.exec(RPC.daemon+' validateaddress "'+address+'"');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.r=='string'){
            try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
            }
        if(typeof o.r=='object'){
            o={
                e:                      (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:{
                    isvalid:            o.r.isvalid==undefined?'missing':o.r.isvalid
                ,   ismine:             o.r.ismine==undefined?'missing':o.r.ismine
                    }
                };
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('validateaddress');}
        return o;
        }
,   stop:function(){
        /*
        stop

        Stop Peony server.
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' stop');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                o={
                    e:                      (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                      o.r==undefined?'missing':o.r.replace('\n','')
                    };
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected string, got '+(typeof o.r);}
            }
        else{o.t=RPC.test('stop');}
        return o;
        }
,   getnewaddress:function(){
        /*
        getnewaddress ( "label" )

        Returns a new PNY address for receiving payments.
        If 'label' is specified, it is added to the address book
        so payments received with the address will be associated with 'label'.

        Arguments:
        1. "label"        (string, optional) The label name for the address to be linked to. if not provided, the default label "" is used. It can also be set to the empty string "" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name.

        Result:
        "PNYaddress"    (string) The new PNY address

        Examples:
        > peony-cli getnewaddress
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' getnewaddress');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                          o.r==undefined?'missing':o.r.replace('\n','')
                    };
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected string, got '+(typeof o.r);}
            }
        else{o.t=RPC.test('getnewaddress');}
        return o;
        }
,   dumpprivkey:function(address,pw){
        /*
        dumpprivkey "peonyaddress"

        Reveals the private key corresponding to 'peonyaddress'.
        Then the importprivkey can be used with this output

        Requires wallet passphrase to be set with walletpassphrase call.

        Arguments:
        1. "peonyaddress"   (string, required) The peony address for the private key

        Result:
        "key"                (string) The private key

        Examples:
        > peony-cli dumpprivkey "myaddress"
        > peony-cli importprivkey "mykey"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "dumpprivkey", "params": ["myaddress"] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/

        importprivkey "peonyprivkey" ( "label" rescan fStakingAddress )

        Adds a private key (as returned by dumpprivkey) to your wallet.

        Requires wallet passphrase to be set with walletpassphrase call.

        Arguments:
        1. "peonyprivkey"      (string, required) The private key (see dumpprivkey)
        2. "label"            (string, optional, default="") An optional label
        3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions

        Note: This call can take minutes to complete if rescan is true.

        Examples:

        Dump a private key
        > peony-cli dumpprivkey "myaddress"

        Import the private key with rescan
        > peony-cli importprivkey "mykey"

        Import using a label and without rescan
        > peony-cli importprivkey "mykey" "testing" false

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "importprivkey", "params": ["mykey", "testing", false] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var o=RPC.signmessage(address,'x',pw,true);//keep open
        if(o.e){
            o={e:o.e,r:undefined};
            }
        else{
            o=RPC.exec(RPC.daemon+' dumpprivkey "'+address+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
            if(typeof o.r=='string'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                          o.r==undefined?'missing':o.r.replace('\n','')
                    };
                var i=RPC.exec(RPC.daemon+' importprivkey "'+o.r+'" "" false');
                if(i.e){
                    o.e=i.e;
                    o.r=undefined;
                    }
                if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                    o.f=true;
                    if(!o.e){o.e='some items are missing';}
                    }
                }
            else{o.j='expected string, got '+(typeof o.r);}
            RPC.walletlock();
            }
        if(RPC.mode=='test'){
            if(o.r){o.r='xxx';}
            o.t=RPC.test('dumpprivkey','( '+RPC.daemon+' help dumpprivkey ;'+RPC.daemon+' help importprivkey )');
            }
        return o;
        }
,   getinfo:function(){
        /*
        getinfo

        Returns an object containing various state info.

        Result:
        {
          "version": xxxxx,             (numeric) the server version
          "protocolversion": xxxxx,     (numeric) the protocol version
          "walletversion": xxxxx,       (numeric) the wallet version
          "balance": xxxxxxx,           (numeric) the total PNY balance of the wallet (excluding zerocoins)
          "zerocoinbalance": xxxxxxx,   (numeric) the total zerocoin balance of the wallet
          "staking status": true|false, (boolean) if the wallet is staking or not
          "blocks": xxxxxx,             (numeric) the current number of blocks processed in the server
          "timeoffset": xxxxx,          (numeric) the time offset
          "connections": xxxxx,         (numeric) the number of connections
          "proxy": "host:port",       (string, optional) the proxy used by the server
          "difficulty": xxxxxx,         (numeric) the current difficulty
          "testnet": true|false,        (boolean) if the server is using testnet or not
          "moneysupply" : "supply"    (numeric) The money supply when this block was added to the blockchain
          "keypoololdest": xxxxxx,      (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool
          "keypoolsize": xxxx,          (numeric) how many new keys are pre-generated
          "unlocked_until": ttt,        (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked
          "paytxfee": x.xxxx,           (numeric) the transaction fee set in PNY/kb
          "relayfee": x.xxxx,           (numeric) minimum relay fee for non-free transactions in PNY/kb
          "errors": "..."             (string) any error messages
        }

        Examples:
        > peony-cli getinfo
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/

        getblockchaininfo
        Returns an object containing various state info regarding block chain processing.

        Result:
        {
          "chain": "xxxx",        (string) current network name as defined in BIP70 (main, test, regtest)
          "blocks": xxxxxx,         (numeric) the current number of blocks processed in the server
          "headers": xxxxxx,        (numeric) the current number of headers we have validated
          "bestblockhash": "...", (string) the hash of the currently best block
          "difficulty": xxxxxx,     (numeric) the current difficulty
          "verificationprogress": xxxx, (numeric) estimate of verification progress [0..1]
          "chainwork": "xxxx"     (string) total amount of work in active chain, in hexadecimal
          "upgrades": {                (object) status of network upgrades
             "name" : {                (string) name of upgrade
                "activationheight": xxxxxx,  (numeric) block height of activation
                "status": "xxxx",      (string) status of upgrade
                "info": "xxxx",        (string) additional information about upgrade
             }, ...
        }

        Examples:
        > peony-cli getblockchaininfo
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockchaininfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:36780/
        */
        var w=RPC.exec(RPC.daemon+' getinfo');
        w.r=w.r==''?undefined:w.r;
        w.e=w.e==''?undefined:JSON.stringify(w.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof w.r=='string'){
            try{
                w.r=JSON.parse(w.r);
                }
            catch(e){w.j=e;}
            }
        if(typeof w.r!='object'){
            w.r={
                errors:     w.j
            ,   balance:    0
                };
            }
        var o=RPC.exec(RPC.daemon+' getblockchaininfo');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.r=='string'){
            try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
            }
        if(typeof o.r=='object'){
            o={
                e:  (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:{
                    errors:                     o.r.warnings||undefined//string
                ,   blocks:                     o.r.blocks==undefined?'missing':o.r.blocks//number
                ,   headers:                    o.r.headers==undefined?'missing':o.r.headers//number
                ,   staking_status:             w.r['staking status']==undefined?'missing':(w.r['staking status']?'Staking Active':'Not Staking')//string
                ,   balance:                    w.r.balance
                    }
                };
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('getinfo','( '+RPC.daemon+' help getinfo ;'+RPC.daemon+' help getblockchaininfo )');}
        return o;
        }
,   resync:function(){
        var o=RPC.exec(RPC.daemon.replace('-cli','d')+' -daemon -resync');
        return;
        }
    };
