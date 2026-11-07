const fs=require('fs'),vm=require('vm'),assert=require('assert');
const sandbox={window:{}};vm.createContext(sandbox);vm.runInContext(fs.readFileSync('root/www/luci-static/resources/observatory/diagnostics-ui.js','utf8'),sandbox);
const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
for(const locale of ['ru','en']){
 const args={snapshot:{devices:[{id:'a',name:'Phone',ips:['192.0.2.1']}]},data:{rows:[{device:'a',kind:'connection',domain:'<img src=x onerror=alert(1)>',first:1,last:2,status:'no_reply',route:'zapret2',source:'Tachyon',protocol:'tcp',port:'443',up:189,down:0}]},device:'a',mode:'issues',search:'',locale,esc,bytes:n=>n+' B',route:r=>esc(r),date:t=>'2026-11-07 '+t};
 const html=sandbox.window.ObservatoryDiagnostics.render(args);
 assert(html.includes('&lt;img'));assert(!html.includes('<img src=x'));assert(html.includes('189 B'));
 assert(html.includes(locale==='ru'?'Подозрение, не доказанная блокировка':'Suspicion, not proof of blocking'));
 assert(sandbox.window.ObservatoryDiagnostics.render({...args,device:'',data:null}).includes('diag-device'));
 assert(sandbox.window.ObservatoryDiagnostics.render({...args,search:'nomatch'}).includes(locale==='ru'?'Нет записей по этому фильтру':'No matching records'));
 const many=Array.from({length:40},(_,i)=>'2001:db8:abcd:1234:1234:1234:1234:'+i.toString(16));
 const compact=sandbox.window.ObservatoryDiagnostics.render({...args,snapshot:{devices:[{id:'a',name:'Test phone',ips:[...many,'192.0.2.42']} ]}});
 const label=compact.match(/<option value="a"[^>]*>([^<]*)<\/option>/)[1];
 assert(label.includes('192.0.2.42'));assert(label.length<80);assert(!label.includes('2001:db8'));
 assert(compact.includes('diag-addresses'));assert(compact.includes(many[39]));
}
console.log('PASS diagnostic renderer RU/EN, filtering, empty selection, HTML escaping');
