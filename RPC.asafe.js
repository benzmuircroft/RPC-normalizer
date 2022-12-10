var exec=require(__dirname+'/../node_modules/shelljs.exec');
var RPC=module.exports={
    daemon:' ASAFE.cli -datadir="/home/ASAFE/data"'
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
,   dir:'ASAFE'
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
,   detecttxtype:function(tx,raw){
        return [audit,'TX-TYPE'];
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
,   peerheightaverage:function(){
        return 1154372;
        }
,   signmessage:function(addr,msg,pw,keepopen){
        /*
        signmessage "allsafeaddress" "message"

        Sign a message with the private key of an address
        Requires wallet passphrase to be set with walletpassphrase call.

        Arguments:
        1. "allsafeaddress"  (string, required) The allsafe address to use for the private key.
        2. "message"         (string, required) The message to create a signature of.

        Result:
        "signature"          (string) The signature of the message encoded in base 64

        Examples:

        Unlock the wallet for 30 seconds
        > allsafe-cli walletpassphrase "mypassphrase" 30

        Create the signature
        > allsafe-cli signmessage "XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg" "my message"

        Verify the signature
        > allsafe-cli verifymessage "XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg" "signature" "my message"

        As json rpc
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signmessage", "params": ["XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg", "my message"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        RPC.walletpassphrase(pw);
        var o=RPC.exec(RPC.daemon+' signmessage "'+addr+'" "'+msg+'"');
        o.r=o.r==''?undefined:(o.r.replace('\n',''));
        o.e=o.e==''?undefined:o.e;
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
          "amount" : x.xxx,        (numeric) The transaction amount in btc
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
              "account" : "accountname",  (string) The account name involved in the transaction, can be "" for the default account.
              "address" : "allsafeaddress",   (string) The allsafe address involved in the transaction
              "category" : "send|receive",    (string) The category, either 'send' or 'receive'
              "amount" : x.xxx                  (numeric) The amount in btc
              "vout" : n,                       (numeric) the vout value
            }
            ,...
          ],
          "hex" : "data"         (string) Raw data for transaction
        }

        Examples:
        > allsafe-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
        > allsafe-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" true
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettransaction", "params": ["1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if(txid!==undefined){//maybe skipped during test
            o=RPC.exec(RPC.daemon+' gettransaction "'+txid+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
               "value" : x.xxx,            (numeric) The value in btc
               "n" : n,                    (numeric) index
               "scriptPubKey" : {          (json object)
                 "asm" : "asm",          (string) the asm
                 "hex" : "hex",          (string) the hex
                 "reqSigs" : n,            (numeric) The required sigs
                 "type" : "pubkeyhash",  (string) The type, eg 'pubkeyhash'
                 "addresses" : [           (json array of string)
                   "12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc"   (string) allsafe address
                   ,...
                 ]
               }
             }
             ,...
          ],
        }

        Examples:
        > allsafe-cli decoderawtransaction "hexstring"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "decoderawtransaction", "params": ["hexstring"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if(hex!==undefined){//maybe skipped during test
            var file='/home/'+RPC.dir+'/'+(+new Date())+'.decoderawtransaction';
            fs.writeFileSync(file,hex,'utf-8');
            o=RPC.exec('DATA=$(cat '+file+'); '+RPC.daemon+' decoderawtransaction "\"${DATA}\""');
            fs.unlinkSync(file);
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
          "value" : x.xxx,           (numeric) The transaction value in btc
          "scriptPubKey" : {         (json object)
             "asm" : "code",       (string)
             "hex" : "hex",        (string)
             "reqSigs" : n,          (numeric) Number of required signatures
             "type" : "pubkeyhash", (string) The type, eg pubkeyhash
             "addresses" : [          (array of string) array of allsafe addresses
             "allsafeaddress"   	 	(string) allsafe address
                ,...
             ]
          },
          "version" : n,            (numeric) The version
          "coinbase" : true|false   (boolean) Coinbase or not
        }

        Examples:

        Get unspent transactions
        > allsafe-cli listunspent

        View the details
        > allsafe-cli gettxout "txid" 1

        As a json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettxout", "params": ["txid", 1] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
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
                o.e=o.e==''?undefined:o.e;
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
          "nonce" : n,           (numeric) The nonce
          "bits" : "1d00ffff", (string) The bits
          "difficulty" : x.xxx,  (numeric) The difficulty
          "previousblockhash" : "hash",  (string) The hash of the previous block
          "nextblockhash" : "hash"       (string) The hash of the next block
          "moneysupply" : "supply"       (numeric) The money supply when this block was added to the blockchain
          "zSAFEsupply" :
          {
             "1" : n,            (numeric) supply of 1 zSAFE denomination
             "5" : n,            (numeric) supply of 5 zSAFE denomination
             "10" : n,           (numeric) supply of 10 zSAFE denomination
             "50" : n,           (numeric) supply of 50 zSAFE denomination
             "100" : n,          (numeric) supply of 100 zSAFE denomination
             "500" : n,          (numeric) supply of 500 zSAFE denomination
             "1000" : n,         (numeric) supply of 1000 zSAFE denomination
             "5000" : n,         (numeric) supply of 5000 zSAFE denomination
             "total" : n,        (numeric) The total supply of all zSAFE denominations
          }
        }

        Result (for verbose=false):
        "data"             (string) A string that is serialized, hex-encoded data for block 'hash'.

        Examples:
        > allsafe-cli getblock "00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblock", "params": ["00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' getblock "'+hash+'"');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
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
        > allsafe-cli getbestblockhash
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getbestblockhash", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' getbestblockhash');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
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
        > allsafe-cli getblockcount
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockcount", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' getblockcount');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
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
        walletpassphrase "passphrase" timeout ( anonymizeonly )

        Stores the wallet decryption key in memory for 'timeout' seconds.
        This is needed prior to performing transactions related to private keys such as sending ALLSAFEs

        Arguments:
        1. "passphrase"     (string, required) The wallet passphrase
        2. timeout            (numeric, required) The time to keep the decryption key in seconds.
        3. anonymizeonly      (boolean, optional, default=flase) If is true sending functions are disabled.
        Note:
        Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock
        time that overrides the old one. A timeout of "0" unlocks until the wallet is closed.

        Examples:

        Unlock the wallet for 60 seconds
        > allsafe-cli walletpassphrase "my pass phrase" 60

        Unlock the wallet for 60 seconds but allow Obfuscation only
        > allsafe-cli walletpassphrase "my pass phrase" 60 true

        Lock the wallet again (before 60 seconds)
        > allsafe-cli walletlock

        As json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "walletpassphrase", "params": ["my pass phrase", 60] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' walletpassphrase "'+p+'" 0 true');//this returns nothing?
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
        o={
            e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
        ,   r:                          (o.e?false:true)
            };
        if(RPC.mode=='test'){o.t=RPC.test('walletlock',RPC.daemon+' help walletpassphrase');}
        return o;
        }
,   walletpassphrase:function(p){
        /*
        walletpassphrase "passphrase" timeout ( anonymizeonly )

        Stores the wallet decryption key in memory for 'timeout' seconds.
        This is needed prior to performing transactions related to private keys such as sending ALLSAFEs

        Arguments:
        1. "passphrase"     (string, required) The wallet passphrase
        2. timeout            (numeric, required) The time to keep the decryption key in seconds.
        3. anonymizeonly      (boolean, optional, default=flase) If is true sending functions are disabled.
        Note:
        Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock
        time that overrides the old one. A timeout of "0" unlocks until the wallet is closed.

        Examples:

        Unlock the wallet for 60 seconds
        > allsafe-cli walletpassphrase "my pass phrase" 60

        Unlock the wallet for 60 seconds but allow Obfuscation only
        > allsafe-cli walletpassphrase "my pass phrase" 60 true

        Lock the wallet again (before 60 seconds)
        > allsafe-cli walletlock

        As json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "walletpassphrase", "params": ["my pass phrase", 60] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' walletpassphrase "'+p+'" 144000 false');//this returns nothing?
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
        o={
            e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
        ,   r:                          (o.e?false:true)
            };
        if(RPC.mode=='test'){o.t=RPC.test('walletpassphrase');}
        return o;
        }
,   listunspent:function(address,min_confirmations){
        /*
        listunspent ( minconf maxconf  ["address",...] )

        Returns array of unspent transaction outputs
        with between minconf and maxconf (inclusive) confirmations.
        Optionally filter to only include txouts paid to specified addresses.
        Results are an array of Objects, each of which has:
        {txid, vout, scriptPubKey, amount, confirmations}

        Arguments:
        1. minconf          (numeric, optional, default=1) The minimum confirmations to filter
        2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter
        3. "addresses"    (string) A json array of allsafe addresses to filter
            [
              "address"   (string) allsafe address
              ,...
            ]

        Result
        [                   (array of json object)
          {
            "txid" : "txid",        (string) the transaction id
            "vout" : n,               (numeric) the vout value
            "address" : "address",  (string) the allsafe address
            "account" : "account",  (string) The associated account, or "" for the default account
            "scriptPubKey" : "key", (string) the script key
            "amount" : x.xxx,         (numeric) the transaction amount in btc
            "confirmations" : n       (numeric) The number of confirmations
          }
          ,...
        ]

        Examples
        > allsafe-cli listunspent
        > allsafe-cli listunspent 6 9999999 "[\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\",\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\"]"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "listunspent", "params": [6, 9999999 "[\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\",\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\"]"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
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
        o.e=o.e==''?undefined:o.e;
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
        createrawtransaction [{"txid":"id","vout":n},...] {"address":amount,...}

        Create a transaction spending the given inputs and sending to the given addresses.
        Returns hex-encoded raw transaction.
        Note that the transaction's inputs are not signed, and
        it is not stored in the wallet or transmitted to the network.

        Arguments:
        1. "transactions"        (string, required) A json array of json objects
             [
               {
                 "txid":"id",  (string, required) The transaction id
                 "vout":n        (numeric, required) The output number
               }
               ,...
             ]
        2. "addresses"           (string, required) a json object with addresses as keys and amounts as values
            {
              "address": x.xxx   (numeric, required) The key is the allsafe address, the value is the btc amount
              ,...
            }

        Result:
        "transaction"            (string) hex string of the transaction

        Examples
        > allsafe-cli createrawtransaction "[{\"txid\":\"myid\",\"vout\":0}]" "{\"address\":0.01}"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "createrawtransaction", "params": ["[{\"txid\":\"myid\",\"vout\":0}]", "{\"address\":0.01}"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' createrawtransaction '+JSON.stringify(JSON.stringify(inputs))+' '+JSON.stringify(JSON.stringify(outputs)));
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
          "hex": "value",   (string) The raw transaction with signature(s) (hex-encoded string)
          "complete": n       (numeric) if transaction has a complete set of signature (0 if not)
        }

        Examples:
        > allsafe-cli signrawtransaction "myhex"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signrawtransaction", "params": ["myhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' signrawtransaction "'+hex+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
            if(typeof o.r=='string'){
                try{o.r=JSON.parse(o.r);}catch(e){o.j=e;}
                }
            if(typeof o.r=='object'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
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
        > allsafe-cli createrawtransaction "[{\"txid\" : \"mytxid\",\"vout\":0}]" "{\"myaddress\":0.01}"
        Sign the transaction, and get back the hex
        > allsafe-cli signrawtransaction "myhex"

        Send the transaction (signed hex)
        > allsafe-cli sendrawtransaction "signedhex"

        As a json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "sendrawtransaction", "params": ["signedhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' sendrawtransaction "'+hex+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
        A locked transaction output will not be chosen by automatic coin selection, when spending ALLSAFEs.
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
        > allsafe-cli listunspent

        Lock an unspent transaction
        > allsafe-cli lockunspent false "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

        List the locked transactions
        > allsafe-cli listlockunspent

        Unlock the transaction again
        > allsafe-cli lockunspent true "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

        As a json rpc call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "lockunspent", "params": [false, "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if([unlock,txid,vout].indexOf(undefined)==-1){//maybe skipped during test
            o=RPC.exec(RPC.daemon+' lockunspent '+unlock+' '+JSON.stringify(JSON.stringify([{txid:txid,vout:vout}])));//this is a bool not an object
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
        estimatefee nblocks

        Estimates the approximate fee per kilobyte
        needed for a transaction to begin confirmation
        within nblocks blocks.

        Arguments:
        1. nblocks     (numeric)

        Result:
        n :    (numeric) estimated fee-per-kilobyte

        -1.0 is returned if not enough transactions and
        blocks have been observed to make an estimate.

        Example:
        > allsafe-cli estimatefee 6
        */
        var o=RPC.exec(RPC.daemon+' getinfo');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
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
        if(RPC.mode=='test'){o.t=RPC.test('estimatefee',RPC.daemon+' help getinfo');}
        return o;
        }
,   validateaddress:function(address){
        /*
        validateaddress "allsafeaddress"

        Return information about the given allsafe address.

        Arguments:
        1. "allsafeaddress"     (string, required) The allsafe address to validate

        Result:
        {
          "isvalid" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.
          "address" : "allsafeaddress", (string) The allsafe address validated
          "ismine" : true|false,          (boolean) If the address is yours or not
          "isscript" : true|false,        (boolean) If the key is a script
          "pubkey" : "publickeyhex",    (string) The hex value of the raw public key
          "iscompressed" : true|false,    (boolean) If the address is compressed
          "account" : "account"         (string) The account associated with the address, "" is the default account
        }

        Examples:
        > allsafe-cli validateaddress "1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "validateaddress", "params": ["1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' validateaddress "'+address+'"');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
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

        Stop AllSafe server.
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' stop');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
        getnewaddress ( "account" )

        Returns a new AllSafe address for receiving payments.
        If 'account' is specified (recommended), it is added to the address book
        so payments received with the address will be credited to 'account'.

        Arguments:
        1. "account"        (string, optional) The account name for the address to be linked to. if not provided, the default account "" is used. It can also be set to the empty string "" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.

        Result:
        "allsafeaddress"    (string) The new allsafe address

        Examples:
        > allsafe-cli getnewaddress
        > allsafe-cli getnewaddress ""
        > allsafe-cli getnewaddress "myaccount"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": ["myaccount"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' getnewaddress');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
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
        dumpprivkey "allsafeaddress"

        Reveals the private key corresponding to 'allsafeaddress'.
        Then the importprivkey can be used with this output

        Arguments:
        1. "allsafeaddress"   (string, required) The allsafe address for the private key

        Result:
        "key"                (string) The private key

        Examples:
        > allsafe-cli dumpprivkey "myaddress"
        > allsafe-cli importprivkey "mykey"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "dumpprivkey", "params": ["myaddress"] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/

        importprivkey "allsafeprivkey" ( "label" rescan )

        Adds a private key (as returned by dumpprivkey) to your wallet.

        Arguments:
        1. "allsafeprivkey"   (string, required) The private key (see dumpprivkey)
        2. "label"            (string, optional, default="") An optional label
        3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions

        Note: This call can take minutes to complete if rescan is true.

        Examples:

        Dump a private key
        > allsafe-cli dumpprivkey "myaddress"

        Import the private key with rescan
        > allsafe-cli importprivkey "mykey"

        Import using a label and without rescan
        > allsafe-cli importprivkey "mykey" "testing" false

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "importprivkey", "params": ["mykey", "testing", false] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.signmessage(address,'x',pw,true);//keep open
        if(o.e){
            o={e:o.e,r:undefined};
            }
        else{
            o=RPC.exec(RPC.daemon+' dumpprivkey "'+address+'"');
            o.r=o.r==''?undefined:o.r;
            o.e=o.e==''?undefined:o.e;
            if(typeof o.r=='string'){
                o={
                    e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
                ,   r:                          o.r==undefined?'missing':o.r.replace('\n','')
                    };
                o.i=RPC.exec(RPC.daemon+' importprivkey "'+o.r+'" "" false');
                if(o.i.e){
                    o.e=o.i.e;
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
          "version": xxxxx,           (numeric) the server version
          "protocolversion": xxxxx,   (numeric) the protocol version
          "walletversion": xxxxx,     (numeric) the wallet version
          "balance": xxxxxxx,         (numeric) the total allsafe balance of the wallet (excluding zerocoins)
          "zerocoinbalance": xxxxxxx, (numeric) the total zerocoin balance of the wallet
          "blocks": xxxxxx,           (numeric) the current number of blocks processed in the server
          "timeoffset": xxxxx,        (numeric) the time offset
          "connections": xxxxx,       (numeric) the number of connections
          "proxy": "host:port",     (string, optional) the proxy used by the server
          "difficulty": xxxxxx,       (numeric) the current difficulty
          "testnet": true|false,      (boolean) if the server is using testnet or not
          "moneysupply" : "supply"       (numeric) The money supply when this block was added to the blockchain
          "zSAFEsupply" :
          {
             "1" : n,            (numeric) supply of 1 zSAFE denomination
             "5" : n,            (numeric) supply of 5 zSAFE denomination
             "10" : n,           (numeric) supply of 10 zSAFE denomination
             "50" : n,           (numeric) supply of 50 zSAFE denomination
             "100" : n,          (numeric) supply of 100 zSAFE denomination
             "500" : n,          (numeric) supply of 500 zSAFE denomination
             "1000" : n,         (numeric) supply of 1000 zSAFE denomination
             "5000" : n,         (numeric) supply of 5000 zSAFE denomination
             "total" : n,        (numeric) The total supply of all zSAFE denominations
          }
          "keypoololdest": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool
          "keypoolsize": xxxx,        (numeric) how many new keys are pre-generated
          "unlocked_until": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked
          "paytxfee": x.xxxx,         (numeric) the transaction fee set in allsafe/kb
          "relayfee": x.xxxx,         (numeric) minimum relay fee for non-free transactions in allsafe/kb
          "staking status": true|false,  (boolean) if the wallet is staking or not
          "errors": "..."           (string) any error messages
        }

        Examples:
        > allsafe-cli getinfo
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:5520/
        */
        var o=RPC.exec(RPC.daemon+' getinfo');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:o.e;
        if(typeof o.r=='string'){
            try{
                o.r=o.r.replace(/staking\sstatus/g,'staking_status');
                o.r=JSON.parse(o.r);
                }
            catch(e){o.j=e;}
            }
        if(typeof o.r=='object'){
            var headers=RPC.getblockcount().r;
            o={
                e:  (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
            ,   r:{
                    errors:                     o.r.errors==undefined?'missing':(o.r.errors==''?undefined:o.r.errors)//string
                ,   blocks:                     o.r.blocks==undefined?'missing':o.r.blocks//number
                ,   headers:                    headers==undefined?'missing':(isNaN(headers)?'missing':(headers+0))//number
                ,   staking_status:             o.r.staking_status==undefined?'missing':o.r.staking_status//string
                ,   balance:                    o.r.balance
                    }
                };
            headers=undefined;
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('getinfo');}
        return o;
        }
,   resync:function(){
        var o=RPC.exec(RPC.daemon.replace('-cli','d')+' -daemon -resync');
        return;
        }
    };
