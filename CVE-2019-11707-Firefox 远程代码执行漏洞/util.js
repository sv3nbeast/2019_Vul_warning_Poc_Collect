/* Utility Functions */

/* Many of these functions maybe poorly written/implemented as they were
   originally meant for one challenge and I was too lazy to rewrite them properly. :)

   This is a poor copy of saelo's Int64 library which can be found here -
   https://github.com/saelo/jscpwn/blob/master/utils.js
*/

String.prototype.rjust = function rjust(n,chr){
  chr = chr || '0'
  if(this.length>n)
    return this.toString();
  return (chr.repeat(n)+this.toString()).slice(-1*n);
}

String.prototype.ljust = function ljust(n,chr){
  chr = chr || '0'
  if(this.length>n)
    return this.toString();
  return (this.toString()+chr.repeat(n)).slice(0,n);
}

String.prototype.hexdecode = function hexdecode(){
  inp=this.toString();
  if (this.length%2 !=0)
  inp='0'+inp.toString();
  out=[];
  for(var i=0;i<inp.length;i+=2)
  out.push(parseInt(inp.substr(i,2),16));
  return out;
}

function print1(num){
  rep='';
  for(var i=0;i<8;i++){
    rep+=num[i].toString(16).rjust(2);
  }
  console.log("0x"+rep.rjust(16));
  // document.getElementById("demo").innerText += "0x"+rep.rjust(16) + '\n';
}


function data(inp){
  bytes='';
  if ( (typeof inp) == 'string'){
    inp=inp.replace("0x",'');
    inp=inp.rjust(16);
    bytes=new Uint8Array(inp.hexdecode());
  }
  else if (typeof inp == 'number'){
    bytes=new Uint8Array(new Float64Array([inp]).buffer);
    bytes.reverse();
  }
  else if (typeof inp == 'object'){
    bytes=new Uint8Array(8);
    bytes.set(inp);
    bytes.reverse();
  }
  return bytes;
}

function inttod(num){
  num.reverse();
  temp = new Float64Array(num.buffer)[0];
  num.reverse();
  return temp;
}

function dtoint(num){
  int=new Uint32Array(new Float64Array([num]).buffer)
  // console.log(int[1].toString(16)+int[0].toString(16));
  return int;
}

function RS(inp,amt){
    amt = amt || 1;
    num='';
    for(var i=0;i<8;i++){
      num+=inp[i].toString(2).rjust(8);
    }
    num=num.slice(0,-1*amt);
    num=num.rjust(64);
    num=parseInt(num,2).toString(16).rjust(16);
    for(var i=0,j=0;i<num.length;i+=2,j++){
      inp[j]=parseInt(num.substr(i,2),16);
    }
    return inp;
}

function LS(inp,amt){
    amt = amt || 1;
    num='';
    for(var i=0;i<8;i++){
      num+=inp[i].toString(2).rjust(8);
    }
    num=num.slice(amt);
    num=num.ljust(64);
    num=parseInt(num,2).toString(16).rjust(16);
    for(var i=0,j=0;i<num.length;i+=2,j++){
      inp[j]=parseInt(num.substr(i,2),16);
    }
    return inp;
}

function sub(inp1,inp2){
    carry=0;
    for(var i=inp1.length-1;i>=0;i--){
        diff=inp1[i]-inp2[i]-carry;
        carry=diff<0|0;
        inp1[i]=diff;
    }
    return inp1;
}

function add(inp1,inp2){
    carry=0;
    for(var i=inp1.length-1;i>=0;i--){
        sum=inp1[i]+inp2[i]+carry;
        carry=sum/0x100;
        inp1[i]=(sum%0x100);
    }
    return inp1;
}

/* Utility functions end */
