// window.onload = async function(){
//     var pktdat_container = document.getElementById("mainpktdatcont");
//     // alert("waiting for dat");
//     let pktdat = await eel.get_packetdat()();
//     // alert("dat received");
//     pktdat_container.innerHTML = pktdat;
//     // alert("dat set");
    
// };

window.onload = async function(){
    let pagetitle = await eel.ret_pktsummaryname()();
    document.title = pagetitle;
};

document.addEventListener("DOMContentLoaded", async function() {
    const jsonViewer = document.getElementById("jsonViewer");
  
    // Example JSON data
    // const jsonData = {
    //   "name": "John",
    //   "age": 30,
    //   "city": "New York",
    //   "children": ["Anna", "Peter", "Tom"]
    // };

    let jsonData = await eel.get_packetdat()();
  
    // Function to create JSON viewer
    function createJSONViewer(data, container) {
      container.innerHTML = ""; // Clear existing content
  
      function createNode(key, value, parent) {
        const node = document.createElement("div");
        node.classList.add("json-node");
  
        if (typeof value === "object") {
          node.classList.add("collapsed");
          node.innerHTML = `<span class="json-property">${key}</span>: <span class="json-value">${typeof value}</span>`;
          const objectNode = document.createElement("div");
          objectNode.classList.add("json-object");
          node.appendChild(objectNode);
          node.addEventListener("click", function() {
            if (node.classList.contains("collapsed")) {
              node.classList.remove("collapsed");
              node.classList.add("expanded");
              objectNode.innerHTML = "";
              Object.entries(value).forEach(([k, v]) => {
                createNode(k, v, objectNode);
              });
            } else {
              node.classList.remove("expanded");
              node.classList.add("collapsed");
              objectNode.innerHTML = "";
            }
          });
        } else {
          node.innerHTML = `<span class="json-property">${key}</span>: <span class="json-value">${JSON.stringify(value)}</span>`;
        }
  
        parent.appendChild(node);
      }
  
      // Iterate over JSON data and create nodes
      Object.entries(data).forEach(([key, value]) => {
        createNode(key, value, container);
      });
    }
  
    // Create JSON viewer
    createJSONViewer(jsonData, jsonViewer);
  });
  