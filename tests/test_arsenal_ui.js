"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const ui = require("../static/arsenal.js");
const response = (data, status=200) => ({ok:status<400,status,text:async()=>JSON.stringify(data)});

test("typed command fields create exact JSON",()=>{
  const data=ui.buildPayload([{name:"target",required:true},{name:"threads",type:"int"},{name:"tls",type:"bool"},{name:"headers",type:"object"}], [{value:"lab.local"},{value:"2"},{checked:true},{value:'{"X-Test":"yes"}'}]);
  assert.equal(data.target,"lab.local"); assert.equal(data.threads,2); assert.equal(data.tls,true); assert.deepEqual(data.headers,{"X-Test":"yes"}); assert.equal(data.authorization_confirmed,true);
});
test("missing or invalid values are rejected",()=>{
  assert.throws(()=>ui.fieldValue({name:"target",required:true},{value:""}),/required/);
  assert.throws(()=>ui.fieldValue({name:"count",type:"int"},{value:"1.5"}),/valid/);
  assert.throws(()=>ui.fieldValue({name:"headers",type:"object"},{value:"[]"}),/object/);
  assert.throws(()=>ui.fieldValue({name:"urls",type:"array"},{value:"{}"}),/array/);
});
test("prototype and confirmation fields cannot override control data",()=>{
  const result=ui.buildPayload([{name:"__proto__"},{name:"authorization_confirmed"}],[{value:"bad"},{value:"false"}]);
  assert.equal(Object.getPrototypeOf(result),null); assert.equal(result.authorization_confirmed,true); assert.equal(result.__proto__,undefined);
});
test("only tool API endpoints accepted",()=>{
  assert.equal(ui.validEndpoint("/api/tools/nmap"),true);
  for(const value of ["/api/command","https://other.invalid/api/tools/nmap","/api/tools/../command","/api/tools/nmap?x=1"]) assert.equal(ui.validEndpoint(value),false);
});
test("HTTP 200 execution failures preserve raw evidence",async()=>{
  await assert.rejects(ui.request(async()=>response({success:false,error:"missing",stdout:"evidence"}),"/api/tools/nmap"),error=>error.data.stdout==="evidence");
});
test("malformed worker output fails clearly",async()=>{
  await assert.rejects(ui.request(async()=>({ok:true,status:200,text:async()=>"bad html"}),"/api/tools/nmap"),/non-JSON/);
});
function launcher(){
  const nodes={};
  const doc={createElement:()=>({value:"",checked:false,style:{},children:[],append(...items){this.children.push(...items);},replaceChildren(){this.children=[];},addEventListener(){}})};
  const instance=new ui.ArsenalLauncher(doc,async()=>response({success:true}));
  for(const name of ["arsenalCategory","arsenalCommand","arsenalFields","arsenalDescription","arsenalReadiness","arsenalAuthorization","arsenalRun","arsenalPreview","arsenalStatus"]){nodes[name]=doc.createElement();}
  instance.nodes=nodes; return instance;
}
test("changing category rebuilds command fields and clears confirmation",()=>{
  const x=launcher(); x.categories=[{id:"network",commands:[{id:"nmap",endpoint:"/api/tools/nmap",fields:[{name:"target",default:"lab.local"}],installed:true}]},{id:"binary",commands:[{id:"xxd",endpoint:"/api/tools/xxd",fields:[{name:"file_path",default:"README.md"}],installed:true}]}];
  x.nodes.arsenalCategory.value="network"; x.selectCategory(); assert.equal(x.command.id,"nmap");
  x.nodes.arsenalAuthorization.checked=true; x.nodes.arsenalCategory.value="binary"; x.selectCategory();
  assert.equal(x.command.id,"xxd"); assert.equal(x.fields[0].name,"file_path"); assert.equal(x.nodes.arsenalAuthorization.checked,false);
});
test("scope confirmation is required before requests",async()=>{
  const x=launcher();let calls=0;x.fetcher=async()=>{calls++;return response({success:true});};
  await x.execute();assert.equal(calls,0);assert.match(x.nodes.arsenalStatus.textContent,/confirm/);
});
test("missing executable cannot be launched",async()=>{
  const x=launcher();let calls=0;x.fetcher=async()=>{calls++;};x.command={endpoint:"/api/tools/nmap",installed:false};x.nodes.arsenalAuthorization.checked=true;
  await x.execute();assert.equal(calls,0);assert.match(x.nodes.arsenalStatus.textContent,/missing/);
});
