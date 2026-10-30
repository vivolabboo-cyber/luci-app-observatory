'use strict';
'require view';
'require rpc';
'require dom';

var readSnapshot = rpc.declare({object:'observatory',method:'snapshot',expect:{}});
var readReport = rpc.declare({object:'observatory',method:'report',params:['hours','device'],expect:{}});

return view.extend({
    render: function() {
        var frame=E('iframe', {src:L.resource('observatory/index.html')+'?v=0.2.1&lang='+encodeURIComponent(document.documentElement.lang||'en'),title:'Observatory',style:'width:100%;border:0;min-height:1100px;background:transparent;',referrerpolicy:'same-origin'});
        var handler=function(event) {
            if(event.origin!==window.location.origin || event.source!==frame.contentWindow)return;
            var msg=event.data;
            if(!msg || msg.type!=='observatory:request' || !Number.isSafeInteger(msg.id))return;
            if(msg.method==='height'){
                var h=Number(msg.height);
                if(Number.isFinite(h))frame.style.height=Math.max(600,Math.min(12000,h))+'px';
                return;
            }
            var task;
            if(msg.method==='snapshot')task=readSnapshot();
            else if(msg.method==='report')task=readReport(Math.max(1,Math.min(168,Number(msg.hours)||24)),String(msg.device||'').slice(0,32));
            else return;
            Promise.resolve(task).then(function(data){frame.contentWindow.postMessage({type:'observatory:response',id:msg.id,data:data},window.location.origin);},function(err){frame.contentWindow.postMessage({type:'observatory:response',id:msg.id,error:String(err)},window.location.origin);});
        };
        window.addEventListener('message',handler);
        return E('div',{},[frame]);
    },
    handleSaveApply:null,
    handleSave:null,
    handleReset:null
});
