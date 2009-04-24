/* darkstat 3
 * copyright (c) 2006-2008 Emil Mikulic.
 *
 * graph.js: graph renderer
 *
 * You may use, modify and redistribute this file under the terms of the
 * GNU General Public License version 2. (see COPYING.GPL)
 *
 * At some point, this script worked correctly in:
 *  - Firefox 1.5.0.4, 2.0.0.1, 3.0
 *  - IE 6.0
 *  - Opera 8.53, 9.50
 *  - Konqueror 3.5.9, 4.0.80, 4.0.83
 *
 * Consumer needs to supply the following variables:
 *  - graph_width
 *  - graph_height
 *  - bar_gap
 *
 *  - graphs [ {id, name, title, bar_secs} ]
 *  - graphs_uri
 *
 *  - window.onload = graphs_init
 */

function killChildren(elem) {
 while (elem.childNodes.length > 0)
  elem.removeChild( elem.childNodes.item(0) );
}

function setClass(elem, c) {
 elem.setAttribute("class", c);
 elem.setAttribute("className", c); /* for MSIE */
}

function setStyle(elem, s) {
 elem.setAttribute("style", s);
 elem.style.cssText = s; /* for MSIE */
}

function makeElemClass(e, c) {
 var r = document.createElement(e);
 setClass(r, c);
 return r;
}

function makeClear() {
 var r = document.createElement("div");
 setStyle(r, "clear:both");
 return r;
}

function thousands(n) {
 var s = String(n);
 var out = "";
 while (s.length > 3) {
  out = "," + s.substr(s.length - 3, 3) + out;
  s = s.substr(0, s.length - 3);
 }
 return s+out;
}

function fkbps(bps) {
 bps /= 1024;
 return bps.toFixed(1);
}

function kbps(bps) {
 bps /= 1024;
 if (bps < 1) return bps.toPrecision(2);
 else return bps.toFixed(1);
}

function min(a,b) { return (a<b)?a:b; }
function max(a,b) { return (a>b)?a:b; }

var xh, autoreload=false;

function graphs_init() {
 var gr = document.getElementById("graphs");

 /* update message */
 var msg = document.createElement("div");
 msg.appendChild(document.createTextNode("Graphs are being loaded..."));
 msg.appendChild(document.createElement("br"));
 msg.appendChild(document.createElement("br"));
 killChildren(gr);
 gr.appendChild(msg);
 graphs.msg = msg;

 for (var i=0; i<graphs.length; i++) {
  var g =  makeElemClass("div", "outergraph");
  gr.appendChild(g);
  graphs[i].graph = g;
  if (i % 2 == 1) gr.appendChild(makeClear());
 }

 /* create buttons */
 var b_reload = document.createElement("a");
 b_reload.setAttribute("id", "graph_reload");
 b_reload.setAttribute("href", "javascript:graph_reload()");
 b_reload.appendChild(document.createTextNode("reload graphs"));

 var b_autoreload = document.createElement("a");
 b_autoreload.setAttribute("id", "graph_autoreload");
 b_autoreload.setAttribute("href", "javascript:graph_autoreload()");
 b_autoreload.appendChild(document.createTextNode("off"));

 var b = document.createElement("div");
 b.appendChild(b_reload);
 b.appendChild(document.createTextNode(" - automatic reload is: "));
 b.appendChild(b_autoreload);
 gr.appendChild(b);

 graph_reload();
}

function graph_reload() {
 if (!autoreload)
  document.getElementById("graph_reload").innerHTML = "loading...";
 xh = (window.ActiveXObject)
  ? new ActiveXObject("Microsoft.XMLHTTP")
  : new XMLHttpRequest();
 var asyncFlag = true;
 xh.open("GET", graphs_uri, asyncFlag);
 // try to nerf caching:
 xh.setRequestHeader("If-Modified-Since", "Sat, 1 Jan 2000 00:00:00 GMT");
 xh.onreadystatechange = poll;
 xh.send(null);
}

function graph_autoreload() {
 // toggle
 autoreload = !autoreload;
 document.getElementById("graph_autoreload").innerHTML =
  autoreload ? "on" : "off";
 if (autoreload) reload_loop();
}

function reload_loop() {
 if (autoreload) {
  graph_reload();
  setTimeout("reload_loop()", 1000);
 }
}

function poll() {
 var STATE_COMPLETE = 4;
 if (xh && xh.readyState == STATE_COMPLETE) {
  for (var i=0; i<graphs.length; i++)
  {
   g = xh.responseXML.getElementsByTagName(graphs[i].name);
   buildGraph(graphs[i].graph, graphs[i].title, graphs[i].bar_secs,
    g[0].getElementsByTagName("e"));
  }
  document.getElementById("graph_reload").innerHTML = "reload graphs";
  killChildren(graphs.msg);
  head = xh.responseXML.childNodes[0];
  for (var n in {"tb":0, "tp":0, "pc":0, "pd":0})
   document.getElementById(n).innerHTML = thousands(head.getAttribute(n));
  document.getElementById("rf").innerHTML = head.getAttribute("rf");
 }
}

function addBar(graph, title, barclass, width, height, left, bottom) {
 if (height == 0) return; /* not visible */
 var bar = makeElemClass("div", barclass);
 bar.setAttribute("title", title);
 setStyle(bar,
  "width:"+width+"px; "+
  "height:"+height+"px; "+
  "position: absolute; "+
  "left:"+left+"px; "+
  "bottom:"+bottom+"px;");
 graph.appendChild(bar);
}

function buildGraph(graph, title, bar_secs, elems) {
 var total_max = 0;
 var data = []; /* list of [in, out] */
 for (var i=0; i<elems.length; i++) {
   var elem = elems.item(i);
   var b_pos = Number( elem.getAttribute("p") );
   var b_in = Number( elem.getAttribute("i") );
   var b_out = Number( elem.getAttribute("o") );
   var b_total = b_in + b_out;
/* FIXME: what happens when a bar's value is >4G? */
   if (b_total > total_max)
    total_max = b_total;
   data.push( [b_pos, b_in, b_out] );
 }

 var igraph = makeElemClass("div", "graph"); // inner graph
 setStyle(igraph,
  "width:"+graph_width+"px; "+
  "height:"+graph_height+"px; "+
  "position:relative;");

 var nbars = data.length;
 var b_width = (graph_width - bar_gap * (nbars-1)) / nbars;
 var next_xofs = 0;

 var min_i = 0, min_o = 0,
     max_i = 0, max_o = 0,
     tot_i = 0, tot_o = 0;

 for (var i=0; i<nbars; i++) {
  var b_p = data[i][0];
  var b_i = data[i][1];
  var b_o = data[i][2];

  if (b_i>0) { if (min_i == 0) min_i = b_i; else min_i = min(min_i, b_i); }
  max_i = max(max_i, b_i);
  tot_i += b_i;

  if (b_o>0) { if (min_o == 0) min_o = b_o; else min_o = min(min_o, b_o); }
  max_o = max(max_o, b_o);
  tot_o += b_o;

  var xofs = next_xofs;

  next_xofs = Math.round((b_width + bar_gap) * (i+1));
  var curr_w = next_xofs - xofs - bar_gap;

  var h_i = Math.round( b_i * graph_height / total_max );
  var h_o = Math.round( b_o * graph_height / total_max );

  var label = b_p+": "+
   thousands(b_i)+" bytes in, "+
   thousands(b_o)+" bytes out | "+
   kbps(b_i/bar_secs)+" KB/s in, "+
   kbps(b_o/bar_secs)+" KB/s out";

  addBar(igraph, label, "bar_in", curr_w, h_i, xofs, 0);
  addBar(igraph, label, "bar_out", curr_w, h_o, xofs, h_i);
 }

 function legendRow(dir_str, minb, avgb, maxb) {
  function makeTD(c, str) {
   var r = makeElemClass("td", c);
   r.appendChild(document.createTextNode(str));
   return r;
  }
  function addToRow(row, type_str, bytes, trail) {
   row.appendChild( makeTD("type", type_str) );
   row.appendChild( makeTD("rate", fkbps(bytes/bar_secs)+" KB/s"+trail) );
  }
  var row = document.createElement("tr");
  row.appendChild( makeTD("dir", dir_str) );
  var cell = makeElemClass("td", "swatch");
  var swatch = makeElemClass("div", "bar_"+dir_str);
  setStyle(swatch, "width:6px; height:6px;");
  cell.appendChild(swatch);
  row.appendChild(cell);
  addToRow(row, "min:", minb, ",");
  addToRow(row, "avg:", avgb, ",");
  addToRow(row, "max:", maxb, "");
  return row;
 }

 var glegend = makeElemClass("div", "legend");
 var avg_i = tot_i / nbars,
     avg_o = tot_o / nbars;
 var tbl = document.createElement("table");
 var tb = document.createElement("tbody"); /* for MSIE */
 tb.appendChild( legendRow("in", min_i, avg_i, max_i) );
 tb.appendChild( legendRow("out", min_o, avg_o, max_o) );
 tbl.appendChild(tb);
 glegend.appendChild(tbl);
 setStyle(glegend, "width:"+graph_width+"px;");

 var gtitle = makeElemClass("div", "graphtitle");
 setStyle(gtitle, "width:"+graph_width+"px;");
 gtitle.appendChild(document.createTextNode(title));

 killChildren(graph);
 graph.appendChild(igraph);
 graph.appendChild(glegend);
 graph.appendChild(gtitle);
}
