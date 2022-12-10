var exec=require(__dirname+'/../node_modules/shelljs.exec');
var RPC=module.exports={
    daemon:' /home/BTC/data/bitcoin-cli -datadir=/home/BTC/data'
    //daemon:' btc q'
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
,   dir:'BTC'
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
        signmessage "address" "message"

        Sign a message with the private key of an address
        Requires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.

        Arguments:
        1. address    (string, required) The bitcoin address to use for the private key.
        2. message    (string, required) The message to create a signature of.

        Result:
        "str"    (string) The signature of the message encoded in base 64

        Examples:

        Unlock the wallet for 30 seconds
        > bitcoin-cli walletpassphrase "mypassphrase" 30

        Create the signature
        > bitcoin-cli signmessage "1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX" "my message"

        Verify the signature
        > bitcoin-cli verifymessage "1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX" "signature" "my message"

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "signmessage", "params": ["1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX", "my message"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        /*
        RPC.walletpassphrase(pw);
        var o=RPC.exec(RPC.daemon+' signmessage "'+addr+'" "'+msg+'"');
        o.r=o.r==''?undefined:(o.r.replace('\n',''));
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(!keepopen){RPC.walletlock();}
        if(RPC.mode=='test'){o.t=RPC.test('signmessage');}
        return o;//this returns error code: -3 error message: Address does not refer to key
        */
        var o=RPC.validateaddress(addr);
        if(o.r.isvalid==true&&o.r.ismine==true&&o.r.solvable==true){
            o.r='success: bitcoin segwit addresses dont sign messages so this with have to do!';
            }
        else{
            o.e='error: not isvalid or ismine or solvable address';
            }
        'we dont test this as it is only used internally!';
        if(keepopen){RPC.walletpassphrase(pw);}
        return o;
        }
,   gettransaction:function(txid){
        /*
        gettransaction "txid" ( include_watchonly verbose )

        Get detailed information about in-wallet transaction <txid>

        Arguments:
        1. txid                 (string, required) The transaction id
        2. include_watchonly    (boolean, optional, default=true for watch-only wallets, otherwise false) Whether to include watch-only addresses in balance calculation and details[]
        3. verbose              (boolean, optional, default=false) Whether to include a `decoded` field containing the decoded transaction (equivalent to RPC decoderawtransaction)

        Result:
        {                                          (json object)
          "amount" : n,                            (numeric) The amount in BTC
          "fee" : n,                               (numeric, optional) The amount of the fee in BTC. This is negative and only available for the
                                                   'send' category of transactions.
          "confirmations" : n,                     (numeric) The number of confirmations for the transaction. Negative confirmations means the
                                                   transaction conflicted that many blocks ago.
          "generated" : true|false,                (boolean, optional) Only present if the transaction's only input is a coinbase one.
          "trusted" : true|false,                  (boolean, optional) Whether we consider the transaction to be trusted and safe to spend from.
                                                   Only present when the transaction has 0 confirmations (or negative confirmations, if conflicted).
          "blockhash" : "hex",                     (string, optional) The block hash containing the transaction.
          "blockheight" : n,                       (numeric, optional) The block height containing the transaction.
          "blockindex" : n,                        (numeric, optional) The index of the transaction in the block that includes it.
          "blocktime" : xxx,                       (numeric, optional) The block time expressed in UNIX epoch time.
          "txid" : "hex",                          (string) The transaction id.
          "walletconflicts" : [                    (json array) Conflicting transaction ids.
            "hex",                                 (string) The transaction id.
            ...
          ],
          "replaced_by_txid" : "hex",              (string, optional) The txid if this tx was replaced.
          "replaces_txid" : "hex",                 (string, optional) The txid if the tx replaces one.
          "comment" : "str",                       (string, optional)
          "to" : "str",                            (string, optional) If a comment to is associated with the transaction.
          "time" : xxx,                            (numeric) The transaction time expressed in UNIX epoch time.
          "timereceived" : xxx,                    (numeric) The time received expressed in UNIX epoch time.
          "comment" : "str",                       (string, optional) If a comment is associated with the transaction, only present if not empty.
          "bip125-replaceable" : "str",            (string) ("yes|no|unknown") Whether this transaction could be replaced due to BIP125 (replace-by-fee);
                                                   may be unknown for unconfirmed transactions not in the mempool.
          "details" : [                            (json array)
            {                                      (json object)
              "involvesWatchonly" : true|false,    (boolean, optional) Only returns true if imported addresses were involved in transaction.
              "address" : "str",                   (string, optional) The bitcoin address involved in the transaction.
              "category" : "str",                  (string) The transaction category.
                                                   "send"                  Transactions sent.
                                                   "receive"               Non-coinbase transactions received.
                                                   "generate"              Coinbase transactions received with more than 100 confirmations.
                                                   "immature"              Coinbase transactions received with 100 or fewer confirmations.
                                                   "orphan"                Orphaned coinbase transactions received.
              "amount" : n,                        (numeric) The amount in BTC
              "label" : "str",                     (string, optional) A comment for the address/transaction, if any
              "vout" : n,                          (numeric) the vout value
              "fee" : n,                           (numeric, optional) The amount of the fee in BTC. This is negative and only available for the
                                                   'send' category of transactions.
              "abandoned" : true|false             (boolean, optional) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the
                                                   'send' category of transactions.
            },
            ...
          ],
          "hex" : "hex",                           (string) Raw data for transaction
          "decoded" : {                            (json object, optional) The decoded transaction (only present when `verbose` is passed)
            ...                                    Equivalent to the RPC decoderawtransaction method, or the RPC getrawtransaction method when `verbose` is passed.
          }
        }

        Examples:
        > bitcoin-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
        > bitcoin-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" true
        > bitcoin-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" false true
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "gettransaction", "params": ["1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o={r:{}};
        if(txid!==undefined){//maybe skipped during test
            o=RPC.exec(RPC.daemon+' gettransaction "'+txid+'"');
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
                    ,   block:                  o.r.blockhash==undefined?'block-not-found':o.r.blockhash//string
                    ,   amount:                 o.r.amount==undefined?'missing':o.r.amount//number
                    ,   fee:                    o.r.fee||undefined//number
                    ,   confirmations:          o.r.confirmations==undefined?'missing':o.r.confirmations//number
                    ,   details:                o.r.details//array
                    ,   generated:              o.r.generated//bool
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
        decoderawtransaction "hexstring" ( iswitness )

        Return a JSON object representing the serialized, hex-encoded transaction.

        Arguments:
        1. hexstring    (string, required) The transaction hex string
        2. iswitness    (boolean, optional, default=depends on heuristic tests) Whether the transaction hex is a serialized witness transaction.
                        If iswitness is not present, heuristic tests will be used in decoding.
                        If true, only witness deserialization will be tried.
                        If false, only non-witness deserialization will be tried.
                        This boolean should reflect whether the transaction has inputs
                        (e.g. fully valid, or on-chain transactions), if known by the caller.

        Result:
        {                             (json object)
          "txid" : "hex",             (string) The transaction id
          "hash" : "hex",             (string) The transaction hash (differs from txid for witness transactions)
          "size" : n,                 (numeric) The transaction size
          "vsize" : n,                (numeric) The virtual transaction size (differs from size for witness transactions)
          "weight" : n,               (numeric) The transaction's weight (between vsize*4 - 3 and vsize*4)
          "version" : n,              (numeric) The version
          "locktime" : xxx,           (numeric) The lock time
          "vin" : [                   (json array)
            {                         (json object)
              "coinbase" : "hex",     (string, optional)
              "txid" : "hex",         (string, optional) The transaction id
              "vout" : n,             (numeric, optional) The output number
              "scriptSig" : {         (json object, optional) The script
                "asm" : "str",        (string) asm
                "hex" : "hex"         (string) hex
              },
              "txinwitness" : [       (json array, optional)
                "hex",                (string) hex-encoded witness data (if any)
                ...
              ],
              "sequence" : n          (numeric) The script sequence number
            },
            ...
          ],
          "vout" : [                  (json array)
            {                         (json object)
              "value" : n,            (numeric) The value in BTC
              "n" : n,                (numeric) index
              "scriptPubKey" : {      (json object)
                "asm" : "str",        (string) the asm
                "desc" : "str",       (string) Inferred descriptor for the output
                "hex" : "hex",        (string) the hex
                "type" : "str",       (string) The type, eg 'pubkeyhash'
                "address" : "str"     (string, optional) The Bitcoin address (only if a well-defined address exists)
              }
            },
            ...
          ]
        }

        Examples:
        > bitcoin-cli decoderawtransaction "hexstring"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "decoderawtransaction", "params": ["hexstring"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o={r:{}};
        if(hex!==undefined){//maybe skipped during test
            var file='/home/'+RPC.dir+'/'+(+new Date())+'.decoderawtransaction';
            fs.writeFileSync(file,hex,'utf-8');
            o=RPC.exec('DATA=$(cat '+file+'); '+RPC.daemon+' decoderawtransaction "\"${DATA}\""');
            fs.unlinkSync(file);
            file=undefined;
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
                            addresses:          o.r.vout[i].scriptPubKey.address==undefined?'can be blank':[o.r.vout[i].scriptPubKey.address]//array of strings
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
        gettxout "txid" n ( include_mempool )

        Returns details about an unspent transaction output.

        Arguments:
        1. txid               (string, required) The transaction id
        2. n                  (numeric, required) vout number
        3. include_mempool    (boolean, optional, default=true) Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear.

        Result (If the UTXO was not found):
        null    (json null)

        Result (Otherwise):
        {                             (json object)
          "bestblock" : "hex",        (string) The hash of the block at the tip of the chain
          "confirmations" : n,        (numeric) The number of confirmations
          "value" : n,                (numeric) The transaction value in BTC
          "scriptPubKey" : {          (json object)
            "asm" : "str",            (string)
            "desc" : "str",           (string) Inferred descriptor for the output
            "hex" : "hex",            (string)
            "type" : "str",           (string) The type, eg pubkeyhash
            "address" : "str"         (string, optional) The Bitcoin address (only if a well-defined address exists)
          },
          "coinbase" : true|false     (boolean) Coinbase or not
        }

        Examples:

        Get unspent transactions
        > bitcoin-cli listunspent

        View the details
        > bitcoin-cli gettxout "txid" 1

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "gettxout", "params": ["txid", 1]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o={r:{}};
        if([txid,vout,addr].indexOf(undefined)==-1){//maybe skipped during test
            o=RPC.signmessage(addr,'x',pw);//replace with dumprivkey
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
        getblock "blockhash" ( verbosity )

        If verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.
        If verbosity is 1, returns an Object with information about block <hash>.
        If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.
        If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).

        Arguments:
        1. blockhash    (string, required) The block hash
        2. verbosity    (numeric, optional, default=1) 0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs

        Result (for verbosity = 0):
        "hex"    (string) A string that is serialized, hex-encoded data for block 'hash'

        Result (for verbosity = 1):
        {                                 (json object)
          "hash" : "hex",                 (string) the block hash (same as provided)
          "confirmations" : n,            (numeric) The number of confirmations, or -1 if the block is not on the main chain
          "size" : n,                     (numeric) The block size
          "strippedsize" : n,             (numeric) The block size excluding witness data
          "weight" : n,                   (numeric) The block weight as defined in BIP 141
          "height" : n,                   (numeric) The block height or index
          "version" : n,                  (numeric) The block version
          "versionHex" : "hex",           (string) The block version formatted in hexadecimal
          "merkleroot" : "hex",           (string) The merkle root
          "tx" : [                        (json array) The transaction ids
            "hex",                        (string) The transaction id
            ...
          ],
          "time" : xxx,                   (numeric) The block time expressed in UNIX epoch time
          "mediantime" : xxx,             (numeric) The median block time expressed in UNIX epoch time
          "nonce" : n,                    (numeric) The nonce
          "bits" : "hex",                 (string) The bits
          "difficulty" : n,               (numeric) The difficulty
          "chainwork" : "hex",            (string) Expected number of hashes required to produce the chain up to this block (in hex)
          "nTx" : n,                      (numeric) The number of transactions in the block
          "previousblockhash" : "hex",    (string, optional) The hash of the previous block (if available)
          "nextblockhash" : "hex"         (string, optional) The hash of the next block (if available)
        }

        Result (for verbosity = 2):
        {                   (json object)
          ...,              Same output as verbosity = 1
          "tx" : [          (json array)
            {               (json object)
              ...,          The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 "tx" result
              "fee" : n     (numeric) The transaction fee in BTC, omitted if block undo data is not available
            },
            ...
          ]
        }

        Result (for verbosity = 3):
        {                                        (json object)
          ...,                                   Same output as verbosity = 2
          "tx" : [                               (json array)
            {                                    (json object)
              "vin" : [                          (json array)
                {                                (json object)
                  ...,                           The same output as verbosity = 2
                  "prevout" : {                  (json object) (Only if undo information is available)
                    "generated" : true|false,    (boolean) Coinbase or not
                    "height" : n,                (numeric) The height of the prevout
                    "value" : n,                 (numeric) The value in BTC
                    "scriptPubKey" : {           (json object)
                      "asm" : "str",             (string) The asm
                      "hex" : "str",             (string) The hex
                      "address" : "str",         (string, optional) The Bitcoin address (only if a well-defined address exists)
                      "type" : "str"             (string) The type (one of: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_scripthash, witness_v0_keyhash, witness_v1_taproot, witness_unknown)
                    }
                  }
                },
                ...
              ]
            },
            ...
          ]
        }

        Examples:
        > bitcoin-cli getblock "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblock", "params": ["00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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

        Returns the hash of the best (tip) block in the most-work fully-validated chain.

        Result:
        "hex"    (string) the block hash, hex-encoded

        Examples:
        > bitcoin-cli getbestblockhash
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getbestblockhash", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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

        Returns the height of the most-work fully-validated chain.
        The genesis block has height 0.

        Result:
        n    (numeric) The current block count

        Examples:
        > bitcoin-cli getblockcount
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
,   walletlock:function(unused){
        /*
        walletlock

        Removes the wallet encryption key from memory, locking the wallet.
        After calling this method, you will need to call walletpassphrase again
        before being able to call any methods which require the wallet to be unlocked.

        Result:
        null    (json null)

        Examples:

        Set the passphrase for 2 minutes to perform a transaction
        > bitcoin-cli walletpassphrase "my pass phrase" 120

        Perform a send (requires passphrase set)
        > bitcoin-cli sendtoaddress "bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl" 1.0

        Clear the passphrase since we are done before 2 minutes is up
        > bitcoin-cli walletlock

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "walletlock", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o=RPC.exec(RPC.daemon+' walletlock');
        o.r=o.r==''?undefined:o.r;
        o.e=o.e==''?undefined:JSON.stringify(o.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(o.r=='null\n'){o.r=undefined;}
        o={
            e:                          (['',null,undefined].indexOf(o.e)!==-1?undefined:o.e)
        ,   r:                          (o.e?false:true)
            };
        if(RPC.mode=='test'){o.t=RPC.test('walletlock');}
        return o;
        }
,   walletpassphrase:function(p){
        /*
        walletpassphrase "passphrase" timeout

        Stores the wallet decryption key in memory for 'timeout' seconds.
        This is needed prior to performing transactions related to private keys such as sending bitcoins

        Note:
        Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock
        time that overrides the old one.

        Arguments:
        1. passphrase    (string, required) The wallet passphrase
        2. timeout       (numeric, required) The time to keep the decryption key in seconds; capped at 100000000 (~3 years).

        Result:
        null    (json null)

        Examples:

        Unlock the wallet for 60 seconds
        > bitcoin-cli walletpassphrase "my pass phrase" 60

        Lock the wallet again (before 60 seconds)
        > bitcoin-cli walletlock

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "walletpassphrase", "params": ["my pass phrase", 60]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o=RPC.exec(RPC.daemon+' walletpassphrase "'+p+'" 144000');//this returns nothing?
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
        listunspent ( minconf maxconf ["address",...] include_unsafe query_options )

        Returns array of unspent transaction outputs
        with between minconf and maxconf (inclusive) confirmations.
        Optionally filter to only include txouts paid to specified addresses.

        Arguments:
        1. minconf                            (numeric, optional, default=1) The minimum confirmations to filter
        2. maxconf                            (numeric, optional, default=9999999) The maximum confirmations to filter
        3. addresses                          (json array, optional, default=[]) The bitcoin addresses to filter
             [
               "address",                     (string) bitcoin address
               ...
             ]
        4. include_unsafe                     (boolean, optional, default=true) Include outputs that are not safe to spend
                                              See description of "safe" attribute below.
        5. query_options                      (json object, optional) JSON with query options
             {
               "minimumAmount": amount,       (numeric or string, optional, default="0.00") Minimum value of each UTXO in BTC
               "maximumAmount": amount,       (numeric or string, optional, default=unlimited) Maximum value of each UTXO in BTC
               "maximumCount": n,             (numeric, optional, default=unlimited) Maximum number of UTXOs
               "minimumSumAmount": amount,    (numeric or string, optional, default=unlimited) Minimum sum value of all UTXOs in BTC
             }

        Result:
        [                                (json array)
          {                              (json object)
            "txid" : "hex",              (string) the transaction id
            "vout" : n,                  (numeric) the vout value
            "address" : "str",           (string, optional) the bitcoin address
            "label" : "str",             (string, optional) The associated label, or "" for the default label
            "scriptPubKey" : "str",      (string) the script key
            "amount" : n,                (numeric) the transaction output amount in BTC
            "confirmations" : n,         (numeric) The number of confirmations
            "ancestorcount" : n,         (numeric, optional) The number of in-mempool ancestor transactions, including this one (if transaction is in the mempool)
            "ancestorsize" : n,          (numeric, optional) The virtual transaction size of in-mempool ancestors, including this one (if transaction is in the mempool)
            "ancestorfees" : n,          (numeric, optional) The total fees of in-mempool ancestors (including this one) with fee deltas used for mining priority in sat (if transaction is in the mempool)
            "redeemScript" : "hex",      (string, optional) The redeemScript if scriptPubKey is P2SH
            "witnessScript" : "str",     (string, optional) witnessScript if the scriptPubKey is P2WSH or P2SH-P2WSH
            "spendable" : true|false,    (boolean) Whether we have the private keys to spend this output
            "solvable" : true|false,     (boolean) Whether we know how to spend this output, ignoring the lack of keys
            "reused" : true|false,       (boolean, optional) (only present if avoid_reuse is set) Whether this output is reused/dirty (sent to an address that was previously spent from)
            "desc" : "str",              (string, optional) (only when solvable) A descriptor for spending this output
            "safe" : true|false          (boolean) Whether this output is considered safe to spend. Unconfirmed transactions
                                         from outside keys and unconfirmed replacement transactions are considered unsafe
                                         and are not eligible for spending by fundrawtransaction and sendtoaddress.
          },
          ...
        ]

        Examples:
        > bitcoin-cli listunspent
        > bitcoin-cli listunspent 6 9999999 "[\"bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl\",\"bc1q02ad21edsxd23d32dfgqqsz4vv4nmtfzuklhy3\"]"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "listunspent", "params": [6, 9999999 "[\"bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl\",\"bc1q02ad21edsxd23d32dfgqqsz4vv4nmtfzuklhy3\"]"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        > bitcoin-cli listunspent 6 9999999 '[]' true '{ "minimumAmount": 0.005 }'
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "listunspent", "params": [6, 9999999, [] , true, { "minimumAmount": 0.005 } ]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
        createrawtransaction [{"txid":"hex","vout":n,"sequence":n},...] [{"address":amount,...},{"data":"hex"},...] ( locktime replaceable )

        Create a transaction spending the given inputs and creating new outputs.
        Outputs can be addresses or data.
        Returns hex-encoded raw transaction.
        Note that the transaction's inputs are not signed, and
        it is not stored in the wallet or transmitted to the network.

        Arguments:
        1. inputs                      (json array, required) The inputs
             [
               {                       (json object)
                 "txid": "hex",        (string, required) The transaction id
                 "vout": n,            (numeric, required) The output number
                 "sequence": n,        (numeric, optional, default=depends on the value of the 'replaceable' and 'locktime' arguments) The sequence number
               },
               ...
             ]
        2. outputs                     (json array, required) The outputs (key-value pairs), where none of the keys are duplicated.
                                       That is, each address can only appear once and there can only be one 'data' object.
                                       For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also
                                       accepted as second parameter.
             [
               {                       (json object)
                 "address": amount,    (numeric or string, required) A key-value pair. The key (string) is the bitcoin address, the value (float or string) is the amount in BTC
                 ...
               },
               {                       (json object)
                 "data": "hex",        (string, required) A key-value pair. The key must be "data", the value is hex-encoded data
               },
               ...
             ]
        3. locktime                    (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs
        4. replaceable                 (boolean, optional, default=false) Marks this transaction as BIP125-replaceable.
                                       Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible.

        Result:
        "hex"    (string) hex string of the transaction

        Examples:
        > bitcoin-cli createrawtransaction "[{\"txid\":\"myid\",\"vout\":0}]" "[{\"address\":0.01}]"
        > bitcoin-cli createrawtransaction "[{\"txid\":\"myid\",\"vout\":0}]" "[{\"data\":\"00010203\"}]"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "createrawtransaction", "params": ["[{\"txid\":\"myid\",\"vout\":0}]", "[{\"address\":0.01}]"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "createrawtransaction", "params": ["[{\"txid\":\"myid\",\"vout\":0}]", "[{\"data\":\"00010203\"}]"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
        signrawtransactionwithwallet "hexstring" ( [{"txid":"hex","vout":n,"scriptPubKey":"hex","redeemScript":"hex","witnessScript":"hex","amount":amount},...] "sighashtype" )

        Sign inputs for raw transaction (serialized, hex-encoded).
        The second optional argument (may be null) is an array of previous transaction outputs that
        this transaction depends on but may not yet be in the block chain.
        Requires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.

        Arguments:
        1. hexstring                        (string, required) The transaction hex string
        2. prevtxs                          (json array, optional) The previous dependent transaction outputs
             [
               {                            (json object)
                 "txid": "hex",             (string, required) The transaction id
                 "vout": n,                 (numeric, required) The output number
                 "scriptPubKey": "hex",     (string, required) script key
                 "redeemScript": "hex",     (string) (required for P2SH) redeem script
                 "witnessScript": "hex",    (string) (required for P2WSH or P2SH-P2WSH) witness script
                 "amount": amount,          (numeric or string) (required for Segwit inputs) the amount spent
               },
               ...
             ]
        3. sighashtype                      (string, optional, default="DEFAULT for Taproot, ALL otherwise") The signature hash type. Must be one of
                                            "DEFAULT"
                                            "ALL"
                                            "NONE"
                                            "SINGLE"
                                            "ALL|ANYONECANPAY"
                                            "NONE|ANYONECANPAY"
                                            "SINGLE|ANYONECANPAY"

        Result:
        {                             (json object)
          "hex" : "hex",              (string) The hex-encoded raw transaction with signature(s)
          "complete" : true|false,    (boolean) If the transaction has a complete set of signatures
          "errors" : [                (json array, optional) Script verification errors (if there are any)
            {                         (json object)
              "txid" : "hex",         (string) The hash of the referenced, previous transaction
              "vout" : n,             (numeric) The index of the output to spent and used as input
              "witness" : [           (json array)
                "hex",                (string)
                ...
              ],
              "scriptSig" : "hex",    (string) The hex-encoded signature script
              "sequence" : n,         (numeric) Script sequence number
              "error" : "str"         (string) Verification or signing error related to the input
            },
            ...
          ]
        }

        Examples:
        > bitcoin-cli signrawtransactionwithwallet "myhex"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "signrawtransactionwithwallet", "params": ["myhex"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o={r:{}};
        if(RPC.mode!=='test'){
            o=RPC.exec(RPC.daemon+' signrawtransactionwithwallet "'+hex+'"');
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
        if(RPC.mode=='test'){o.t=RPC.test('signrawtransaction',RPC.daemon+' help signrawtransactionwithwallet');}
        return o;
        }
,   sendrawtransaction:function(hex){
        /*
        sendrawtransaction "hexstring" ( maxfeerate )

        Submit a raw transaction (serialized, hex-encoded) to local node and network.

        The transaction will be sent unconditionally to all peers, so using sendrawtransaction
        for manual rebroadcast may degrade privacy by leaking the transaction's origin, as
        nodes will normally not rebroadcast non-wallet transactions already in their mempool.

        A specific exception, RPC_TRANSACTION_ALREADY_IN_CHAIN, may throw if the transaction cannot be added to the mempool.

        Related RPCs: createrawtransaction, signrawtransactionwithkey

        Arguments:
        1. hexstring     (string, required) The hex string of the raw transaction
        2. maxfeerate    (numeric or string, optional, default="0.10") Reject transactions whose fee rate is higher than the specified value, expressed in BTC/kvB.
                         Set to 0 to accept any fee rate.


        Result:
        "hex"    (string) The transaction hash in hex

        Examples:

        Create a transaction
        > bitcoin-cli createrawtransaction "[{\"txid\" : \"mytxid\",\"vout\":0}]" "{\"myaddress\":0.01}"
        Sign the transaction, and get back the hex
        > bitcoin-cli signrawtransactionwithwallet "myhex"

        Send the transaction (signed hex)
        > bitcoin-cli sendrawtransaction "signedhex"

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "sendrawtransaction", "params": ["signedhex"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
        lockunspent unlock ( [{"txid":"hex","vout":n},...] persistent )

        Updates list of temporarily unspendable outputs.
        Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.
        If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.
        A locked transaction output will not be chosen by automatic coin selection, when spending bitcoins.
        Manually selected coins are automatically unlocked.
        Locks are stored in memory only, unless persistent=true, in which case they will be written to the
        wallet database and loaded on node start. Unwritten (persistent=false) locks are always cleared
        (by virtue of process exit) when a node stops or fails. Unlocking will clear both persistent and not.
        Also see the listunspent call

        Arguments:
        1. unlock                  (boolean, required) Whether to unlock (true) or lock (false) the specified transactions
        2. transactions            (json array, optional, default=[]) The transaction outputs and within each, the txid (string) vout (numeric).
             [
               {                   (json object)
                 "txid": "hex",    (string, required) The transaction id
                 "vout": n,        (numeric, required) The output number
               },
               ...
             ]
        3. persistent              (boolean, optional, default=false) Whether to write/erase this lock in the wallet database, or keep the change in memory only. Ignored for unlocking.

        Result:
        true|false    (boolean) Whether the command was successful or not

        Examples:

        List the unspent transactions
        > bitcoin-cli listunspent

        Lock an unspent transaction
        > bitcoin-cli lockunspent false "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

        List the locked transactions
        > bitcoin-cli listlockunspent

        Unlock the transaction again
        > bitcoin-cli lockunspent true "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

        Lock the transaction persistently in the wallet database
        > bitcoin-cli lockunspent false "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]" true

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "lockunspent", "params": [false, "[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
        {                                                    (json object)
          "version" : n,                                     (numeric) the server version
          "subversion" : "str",                              (string) the server subversion string
          "protocolversion" : n,                             (numeric) the protocol version
          "localservices" : "hex",                           (string) the services we offer to the network
          "localservicesnames" : [                           (json array) the services we offer to the network, in human-readable form
            "str",                                           (string) the service name
            ...
          ],
          "localrelay" : true|false,                         (boolean) true if transaction relay is requested from peers
          "timeoffset" : n,                                  (numeric) the time offset
          "connections" : n,                                 (numeric) the total number of connections
          "connections_in" : n,                              (numeric) the number of inbound connections
          "connections_out" : n,                             (numeric) the number of outbound connections
          "networkactive" : true|false,                      (boolean) whether p2p networking is enabled
          "networks" : [                                     (json array) information per network
            {                                                (json object)
              "name" : "str",                                (string) network (ipv4, ipv6, onion, i2p, cjdns)
              "limited" : true|false,                        (boolean) is the network limited using -onlynet?
              "reachable" : true|false,                      (boolean) is the network reachable?
              "proxy" : "str",                               (string) ("host:port") the proxy that is used for this network, or empty if none
              "proxy_randomize_credentials" : true|false     (boolean) Whether randomized credentials are used
            },
            ...
          ],
          "relayfee" : n,                                    (numeric) minimum relay fee rate for transactions in BTC/kvB
          "incrementalfee" : n,                              (numeric) minimum fee rate increment for mempool limiting or BIP 125 replacement in BTC/kvB
          "localaddresses" : [                               (json array) list of local addresses
            {                                                (json object)
              "address" : "str",                             (string) network address
              "port" : n,                                    (numeric) network port
              "score" : n                                    (numeric) relative score
            },
            ...
          ],
          "warnings" : "str"                                 (string) any network and blockchain warnings
        }

        Examples:
        > bitcoin-cli getnetworkinfo
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getnetworkinfo", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
        validateaddress "address"

        Return information about the given bitcoin address.

        Arguments:
        1. address    (string, required) The bitcoin address to validate

        Result:
        {                               (json object)
          "isvalid" : true|false,       (boolean) If the address is valid or not
          "address" : "str",            (string, optional) The bitcoin address validated
          "scriptPubKey" : "hex",       (string, optional) The hex-encoded scriptPubKey generated by the address
          "isscript" : true|false,      (boolean, optional) If the key is a script
          "iswitness" : true|false,     (boolean, optional) If the address is a witness address
          "witness_version" : n,        (numeric, optional) The version number of the witness program
          "witness_program" : "hex",    (string, optional) The hex value of the witness program
          "error" : "str",              (string, optional) Error message, if any
          "error_locations" : [         (json array, optional) Indices of likely error locations in address, if known (e.g. Bech32 errors)
            n,                          (numeric) index of a potential error
            ...
          ]
        }

        Examples:
        > bitcoin-cli validateaddress "bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "validateaddress", "params": ["bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/

        getaddressinfo "address"

        Return information about the given bitcoin address.
        Some of the information will only be present if the address is in the active wallet.

        Arguments:
        1. address    (string, required) The bitcoin address for which to get information.

        Result:
        {                                   (json object)
          "address" : "str",                (string) The bitcoin address validated.
          "scriptPubKey" : "hex",           (string) The hex-encoded scriptPubKey generated by the address.
          "ismine" : true|false,            (boolean) If the address is yours.
          "iswatchonly" : true|false,       (boolean) If the address is watchonly.
          "solvable" : true|false,          (boolean) If we know how to spend coins sent to this address, ignoring the possible lack of private keys.
          "desc" : "str",                   (string, optional) A descriptor for spending coins sent to this address (only when solvable).
          "parent_desc" : "str",            (string, optional) The descriptor used to derive this address if this is a descriptor wallet
          "isscript" : true|false,          (boolean) If the key is a script.
          "ischange" : true|false,          (boolean) If the address was used for change output.
          "iswitness" : true|false,         (boolean) If the address is a witness address.
          "witness_version" : n,            (numeric, optional) The version number of the witness program.
          "witness_program" : "hex",        (string, optional) The hex value of the witness program.
          "script" : "str",                 (string, optional) The output script type. Only if isscript is true and the redeemscript is known. Possible
                                            types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash,
                                            witness_v0_scripthash, witness_unknown.
          "hex" : "hex",                    (string, optional) The redeemscript for the p2sh address.
          "pubkeys" : [                     (json array, optional) Array of pubkeys associated with the known redeemscript (only if script is multisig).
            "str",                          (string)
            ...
          ],
          "sigsrequired" : n,               (numeric, optional) The number of signatures required to spend multisig output (only if script is multisig).
          "pubkey" : "hex",                 (string, optional) The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH).
          "embedded" : {                    (json object, optional) Information about the address embedded in P2SH or P2WSH, if relevant and known.
            ...                             Includes all getaddressinfo output fields for the embedded address, excluding metadata (timestamp, hdkeypath, hdseedid)
                                            and relation to the wallet (ismine, iswatchonly).
          },
          "iscompressed" : true|false,      (boolean, optional) If the pubkey is compressed.
          "timestamp" : xxx,                (numeric, optional) The creation time of the key, if available, expressed in UNIX epoch time.
          "hdkeypath" : "str",              (string, optional) The HD keypath, if the key is HD and available.
          "hdseedid" : "hex",               (string, optional) The Hash160 of the HD seed.
          "hdmasterfingerprint" : "hex",    (string, optional) The fingerprint of the master key.
          "labels" : [                      (json array) Array of labels associated with the address. Currently limited to one label but returned
                                            as an array to keep the API stable if multiple labels are enabled in the future.
            "str",                          (string) Label name (defaults to "").
            ...
          ]
        }

        Examples:
        > bitcoin-cli getaddressinfo "bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getaddressinfo", "params": ["bc1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var o={};
        o.v=RPC.exec(RPC.daemon+' validateaddress "'+address+'"');
        o.v.r=o.v.r==''?undefined:o.v.r;
        o.v.e=o.v.e==''?undefined:JSON.stringify(o.v.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.v.r=='string'){
            try{o.v.r=JSON.parse(o.v.r);}catch(e){o.j=e;}
            }
        o.a=RPC.exec(RPC.daemon+' getaddressinfo "'+address+'"');
        o.a.r=o.a.r==''?undefined:o.a.r;
        o.a.e=o.a.e==''?undefined:JSON.stringify(o.a.e).replace(/\\/g,'').replace(/\"/g,"'");
        if(typeof o.a.r=='string'){
            try{o.a.r=JSON.parse(o.a.r);}catch(e){o.j=e;}
            }
        if(typeof o.v.r=='object'&&typeof o.a.r=='object'){
            o={
                e:                      (['',null,undefined].indexOf(o.v.e)!==-1?(['',null,undefined].indexOf(o.a.e)!==-1?undefined:o.a.e):o.v.e)
            ,   r:{
                    isvalid:            o.v.r.isvalid==undefined?'missing':o.v.r.isvalid
                ,   ismine:             o.a.r.ismine==undefined?'missing':o.a.r.ismine
                ,   solvable:           o.a.r.solvable==undefined?'missing':o.a.r.solvable
                    }
                };
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='validateaddress expected object, got '+(typeof o.v.r)+' getaddressinfo expected object, got '+(typeof o.a.r);}
        if(RPC.mode=='test'){o.t=RPC.test('validateaddress','( '+RPC.daemon+' help validateaddress ;'+RPC.daemon+' help getaddressinfo )');}
        return o;
        }
,   stop:function(){
        /*
        stop

        Request a graceful shutdown of Bitcoin Core.

        Result:
        "str"    (string) A string with the content 'Bitcoin Core stopping'
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
        getnewaddress ( "label" "address_type" )

        Returns a new Bitcoin address for receiving payments.
        If 'label' is specified, it is added to the address book
        so payments received with the address will be associated with 'label'.

        Arguments:
        1. label           (string, optional, default="") The label name for the address to be linked to. It can also be set to the empty string "" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name.
        2. address_type    (string, optional, default=set by -addresstype) The address type to use. Options are "legacy", "p2sh-segwit", "bech32", and "bech32m".

        Result:
        "str"    (string) The new bitcoin address

        Examples:
        > bitcoin-cli getnewaddress
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getnewaddress", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
        dumpprivkey "address"

        Reveals the private key corresponding to 'address'.
        Then the importprivkey can be used with this output

        Arguments:
        1. address    (string, required) The bitcoin address for the private key

        Result:
        "str"    (string) The private key

        Examples:
        > bitcoin-cli dumpprivkey "myaddress"
        > bitcoin-cli importprivkey "mykey"
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "dumpprivkey", "params": ["myaddress"]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/

        importprivkey "privkey" ( "label" rescan )

        Adds a private key (as returned by dumpprivkey) to your wallet. Requires a new wallet backup.
        Hint: use importmulti to import more than one private key.

        Note: This call can take over an hour to complete if rescan is true, during that time, other rpc calls
        may report that the imported key exists but related transactions are still missing, leading to temporarily incorrect/bogus balances and unspent outputs until rescan completes.
        Note: Use "getwalletinfo" to query the scanning progress.

        Arguments:
        1. privkey    (string, required) The private key (see dumpprivkey)
        2. label      (string, optional, default=current label if address exists, otherwise "") An optional label
        3. rescan     (boolean, optional, default=true) Rescan the wallet for transactions

        Result:
        null    (json null)

        Examples:

        Dump a private key
        > bitcoin-cli dumpprivkey "myaddress"

        Import the private key with rescan
        > bitcoin-cli importprivkey "mykey"

        Import using a label and without rescan
        > bitcoin-cli importprivkey "mykey" "testing" false

        Import using default blank label and without rescan
        > bitcoin-cli importprivkey "mykey" "" false

        As a JSON-RPC call
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "importprivkey", "params": ["mykey", "testing", false]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
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
            'RPC.walletlock(); does not need to happen as bitcoin does not signmessage so wallet is not unlocked';
            }
        if(RPC.mode=='test'){
            if(o.r){o.r='xxx';}
            o.t=RPC.test('dumpprivkey','( '+RPC.daemon+' help dumpprivkey ;'+RPC.daemon+' help importprivkey )');
            }
        return o;
        }
,   getinfo:function(){
        /*
        getbalances

        Returns an object with all balances in BTC.

        Result:
        {                               (json object)
          "mine" : {                    (json object) balances from outputs that the wallet can sign
            "trusted" : n,              (numeric) trusted balance (outputs created by the wallet or confirmed outputs)
            "untrusted_pending" : n,    (numeric) untrusted pending balance (outputs created by others that are in the mempool)
            "immature" : n,             (numeric) balance from immature coinbase outputs
            "used" : n                  (numeric, optional) (only present if avoid_reuse is set) balance from coins sent to addresses that were previously spent from (potentially privacy violating)
          },
          "watchonly" : {               (json object, optional) watchonly balances (not present if wallet does not watch anything)
            "trusted" : n,              (numeric) trusted balance (outputs created by the wallet or confirmed outputs)
            "untrusted_pending" : n,    (numeric) untrusted pending balance (outputs created by others that are in the mempool)
            "immature" : n              (numeric) balance from immature coinbase outputs
          }
        }

        Examples:
        > bitcoin-cli getbalances
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getbalances", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/

        getblockchaininfo

        Returns an object containing various state info regarding blockchain processing.

        Result:
        {                                         (json object)
          "chain" : "str",                        (string) current network name (main, test, signet, regtest)
          "blocks" : n,                           (numeric) the height of the most-work fully-validated chain. The genesis block has height 0
          "headers" : n,                          (numeric) the current number of headers we have validated
          "bestblockhash" : "str",                (string) the hash of the currently best block
          "difficulty" : n,                       (numeric) the current difficulty
          "time" : xxx,                           (numeric) The block time expressed in UNIX epoch time
          "mediantime" : xxx,                     (numeric) The median block time expressed in UNIX epoch time
          "verificationprogress" : n,             (numeric) estimate of verification progress [0..1]
          "initialblockdownload" : true|false,    (boolean) (debug information) estimate of whether this node is in Initial Block Download mode
          "chainwork" : "hex",                    (string) total amount of work in active chain, in hexadecimal
          "size_on_disk" : n,                     (numeric) the estimated size of the block and undo files on disk
          "pruned" : true|false,                  (boolean) if the blocks are subject to pruning
          "pruneheight" : n,                      (numeric, optional) lowest-height complete block stored (only present if pruning is enabled)
          "automatic_pruning" : true|false,       (boolean, optional) whether automatic pruning is enabled (only present if pruning is enabled)
          "prune_target_size" : n,                (numeric, optional) the target size used by pruning (only present if automatic pruning is enabled)
          "softforks" : {                         (json object) (DEPRECATED, returned only if config option -deprecatedrpc=softforks is passed) status of softforks
            "xxxx" : {                            (json object) name of the softfork
              "type" : "str",                     (string) one of "buried", "bip9"
              "height" : n,                       (numeric, optional) height of the first block which the rules are or will be enforced (only for "buried" type, or "bip9" type with "active" status)
              "active" : true|false,              (boolean) true if the rules are enforced for the mempool and the next block
              "bip9" : {                          (json object, optional) status of bip9 softforks (only for "bip9" type)
                "bit" : n,                        (numeric, optional) the bit (0-28) in the block version field used to signal this softfork (only for "started" and "locked_in" status)
                "start_time" : xxx,               (numeric) the minimum median time past of a block at which the bit gains its meaning
                "timeout" : xxx,                  (numeric) the median time past of a block at which the deployment is considered failed if not yet locked in
                "min_activation_height" : n,      (numeric) minimum height of blocks for which the rules may be enforced
                "status" : "str",                 (string) status of deployment at specified block (one of "defined", "started", "locked_in", "active", "failed")
                "since" : n,                      (numeric) height of the first block to which the status applies
                "status_next" : "str",            (string) status of deployment at the next block
                "statistics" : {                  (json object, optional) numeric statistics about signalling for a softfork (only for "started" and "locked_in" status)
                  "period" : n,                   (numeric) the length in blocks of the signalling period
                  "threshold" : n,                (numeric, optional) the number of blocks with the version bit set required to activate the feature (only for "started" status)
                  "elapsed" : n,                  (numeric) the number of blocks elapsed since the beginning of the current period
                  "count" : n,                    (numeric) the number of blocks with the version bit set in the current period
                  "possible" : true|false         (boolean, optional) returns false if there are not enough blocks left in this period to pass activation threshold (only for "started" status)
                },
                "signalling" : "str"              (string) indicates blocks that signalled with a # and blocks that did not with a -
              }
            },
            ...
          },
          "warnings" : "str"                      (string) any network and blockchain warnings
        }

        Examples:
        > bitcoin-cli getblockchaininfo
        > curl --user myusername --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockchaininfo", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
        */
        var w=RPC.exec(RPC.daemon+' getbalances');
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
            ,   mine:{
                    trusted:0
                    }
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
                ,   staking_status:             'Not A Staking Coin'//string
                ,   balance:                    w.r.mine.trusted
                    }
                };
            if(JSON.stringify(o).indexOf(':"missing"')!==-1){
                o.f=true;
                if(!o.e){o.e='some items are missing';}
                }
            }
        else{o.j='expected object, got '+(typeof o.r);}
        if(RPC.mode=='test'){o.t=RPC.test('getinfo','( '+RPC.daemon+' help getbalances ;'+RPC.daemon+' help getblockchaininfo )');}
        return o;
        }
,   resync:function(){
        var o=RPC.exec(RPC.daemon.replace('-cli','d')+' -daemon');//-resync was removed and happens automatically if needed
        return;
        }
    };
