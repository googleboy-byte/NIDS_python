var allpkts_prev = [];
var nidsflaggedpkts_prev = [];
var clearinglists = false;

function mainpkts_anchor_in_viewport(){
    var scrollableDiv1 = document.getElementById("mainpktstreamcont");
    var anchorelement1 = document.getElementById("anchorelement_mainpktstream");
    var rect1 = anchorelement1.getBoundingClientRect();
    var scrollableDivRect1 = scrollableDiv1.getBoundingClientRect();

    return (
        rect1.top + 1 >= scrollableDivRect1.top &&
        rect1.bottom - 1 <= scrollableDivRect1.bottom
    );
}

async function update_allpkts(){
    if (clearinglists == false){
        var mainpktsdiv = document.getElementById("mainpktstreamcont");
        // mainpktsdiv.innerHTML = "";
        let autoscroll_mainstream = "FALSE";
        let pktsummarylist = await eel.update_allpackets_gui()();
        var newpktsummarylist = pktsummarylist.filter(item => !allpkts_prev.includes(item));
        if(mainpkts_anchor_in_viewport()){
            autoscroll_mainstream = "TRUE";
        }
        newpktsummarylist.forEach(packetsummary => {
            var newpktdiv = document.createElement("div");
            newpktdiv.style.borderBottom = "1px solid black";
            newpktdiv.style.borderLeft = "1px solid black";
            newpktdiv.style.borderRight = "1px solid black";
            newpktdiv.innerText = " " + packetsummary;
            if (packetsummary.includes("suspkt_idx")){
                newpktdiv.style.backgroundColor = "#a03939b0";
                newpktdiv.style.color = "antiquewhite";
            }
            newpktdiv.onclick = async function(){
                let pkt_data = await eel.show_mainstream_packet(packetsummary)();
                // alert(pkt_data);
                var gb2 = document.getElementById("lastpktcont");
                gb2.innerHTML = "";
                
                var btnopenpacket = document.createElement("div");
                btnopenpacket.id = pkt_data["pktid"];
                btnopenpacket.innerHTML = "VIEW PACKET";
                btnopenpacket.className = "openpkt_btn";
                btnopenpacket.onclick = function(){
                    eel.show_packet(pkt_data["pktid"]);
                };

                var sourcechild = document.createElement("div");
                var destchild = document.createElement("div");
                var protochild = document.createElement("div");
                var payloadchild = document.createElement("div");
                var rawchild = document.createElement("div");

                sourcechild.className = "pktdat_lastpktcont";
                destchild.className = "pktdat_lastpktcont";
                protochild.className = "pktdat_lastpktcont";
                payloadchild.className = "pktdat_lastpktcont";
                rawchild.className = "pktdat_lastpktcont";

                sourcechild.innerHTML = "Source: " + pkt_data["srcip"];
                destchild.innerHTML = "Destination: " + pkt_data["destip"];
                protochild.innerHTML = "Protocol: " + pkt_data["proto"];
                payloadchild.innerHTML = "Payload: " + pkt_data["payload"];
                rawchild.innerHTML = "Raw: " + pkt_data["raw"];
  
                gb2.appendChild(btnopenpacket);
                gb2.appendChild(sourcechild);
                gb2.appendChild(destchild);
                gb2.appendChild(protochild);
                gb2.appendChild(payloadchild);
                gb2.appendChild(rawchild);

            };
            // mainpktsdiv.appendChild(newpktdiv);
            var mainstreamanchorelement = document.getElementById("anchorelement_mainpktstream");
            mainpktsdiv.insertBefore(newpktdiv, mainstreamanchorelement);
        });
        if(autoscroll_mainstream == "TRUE"){
            mainpktsdiv.scrollTop = mainpktsdiv.scrollHeight;
        }
        allpkts_prev = pktsummarylist;
    }
}


function suspkts_anchor_in_viewport(){
    var scrollableDiv = document.getElementById("nidsflaggedpackets");
    var anchorelement = document.getElementById("anchorelement_nidsflaggedpackets");
    var rect = anchorelement.getBoundingClientRect();
    var scrollableDivRect = scrollableDiv.getBoundingClientRect();

    return (
        rect.top >= scrollableDivRect.top &&
        rect.bottom <= scrollableDivRect.bottom
    );
}

async function update_nidsflaggedpkts(){
    if (clearinglists ==  false){
        var suspktsdiv = document.getElementById("nidsflaggedpackets");
        // mainpktsdiv.innerHTML = "";
        // suspktsdiv.classList.toggle("atBottom", isScrollAtBottom());
        let autoscroll_suspkts = "FALSE";
        let suspktslist = await eel.update_allpackets_nidsflagged_gui()();
        var newsuspktslist = suspktslist.filter(item => !nidsflaggedpkts_prev.includes(item));
        if(suspkts_anchor_in_viewport()){
            autoscroll_suspkts = "TRUE";
        }
        newsuspktslist.forEach(suspacketsummary => {
            var newsuspktdiv = document.createElement("div");
            newsuspktdiv.style.backgroundColor = "#a03939b0";
            newsuspktdiv.style.color = "antiquewhite";
            // newsuspktdiv.style.borderTop = "1px solid black";
            newsuspktdiv.style.borderBottom = "2px solid black"
            newsuspktdiv.style.width = "100%";
            newsuspktdiv.innerText = suspacketsummary;
            // newsuspktdiv.style.overflowAnchor = "auto";
            newsuspktdiv.onclick = async function(){
                let pktdata = await eel.show_nidsflagged_packet(suspacketsummary)();
                var gb2 = document.getElementById("lastpktcont");
                gb2.innerHTML = pktdata;
            };
            // let elemcnt1 = document.getElementById("nidsflaggedpackets").childElementCount;
            var anchorelement = document.getElementById("anchorelement_nidsflaggedpackets");
            suspktsdiv.insertBefore(newsuspktdiv, anchorelement);
            // suspktsdiv.appendChild(newsuspktdiv);   
        });
        // if(Math.abs(suspktsdiv.scrollHeight - suspktsdiv.scrollTop - suspktsdiv.clientHeight) > 1){
        //     suspktsdiv.style.overflowAnchor = "auto";
        // }
        
        if(autoscroll_suspkts == "TRUE"){
            // alert("updating scroll")    
            suspktsdiv.scrollTop = suspktsdiv.scrollHeight;
        }
        
        nidsflaggedpkts_prev = suspktslist;
    }
}


function refreshrules_call(){
    // alert("Refresh rules?");
    eel.refreshrules();
    // alert("Rules refreshed");
}

async function stopcap(){
    await eel.pausecap()();
}

async function resumecap(){
    await eel.resumecap()();
}

async function clearall(){
    clearinglists = true;
    allpkts_prev = [];
    nidsflaggedpkts_prev = [];
    await eel.clearall()();
    var suspktsdiv = document.getElementById("nidsflaggedpackets");
    suspktsdiv.innerHTML = "";
    var mainpktsdiv = document.getElementById("mainpktstreamcont");
    mainpktsdiv.innerHTML = "";
    // alert("Cleared...")
    // await new Promise(r => setTimeout(r, 5000));
    clearinglists = false;
    await eel.resumecap()();
}

async function loadstreams(){
    let tcp_http_streams = await eel.load_streams()();
    var streamcontdiv = document.getElementById("streamscont");
    streamcontdiv.innerHTML = "";
    tcp_http_streams.forEach(stream => {
        var newstreamdiv = document.createElement("div");
        newstreamdiv.style.borderBottom = "1px solid black";
        newstreamdiv.style.borderLeft = "1px solid black";
        newstreamdiv.style.borderRight = "1px solid black";
        newstreamdiv.id = stream;
        newstreamdiv.innerHTML = stream;
        newstreamdiv.onclick = async function(){
            var streamdat = await eel.show_stream_data(stream)();
            var stream_modal_div = document.getElementById("stream_show_modal");
            stream_modal_div.style.display = "block";
            var modalcontentdiv = document.getElementById("stream_modalcontent");
            modalcontentdiv.innerHTML = streamdat;
        };
        streamcontdiv.appendChild(newstreamdiv);
    });
}

function close_stream_show_modal(){
    var modaldiv = document.getElementById("stream_show_modal");
    modaldiv.style.display = "none";
}


setInterval(update_allpkts, 10)
setInterval(update_nidsflaggedpkts, 10);

// window.onload = function(){
//     var suspktsdivelement = document.getElementById("nidsflaggedpackets");
//     var suspkt_anchorelem = document.createElement("div");
//     suspkt_anchorelem.style.overflowAnchor = "auto";
//     suspkt_anchorelem.style.height = "1px";
//     suspktsdivelement.appendChild(suspkt_anchorelem);
//     // suspktsdivelement.scroll(0, 1);
// }

// window.onresize = function (){
//     if (window.outerWidth < 1200 || window.outerHeight < 800){
//         window.resizeTo(1200, 800);
//     }
// }