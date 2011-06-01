<?php
# copyright (c) 2011 Malte S. Stretz
#
# This is a simple proxy script to test the proper implementation of
# relative hrefs in combination with eg. lighttpd 1.4 which doesn't
# support the features of mod_proxy_core yet.

$darkstat = "http://localhost:667";

if ($_SERVER['PATH_INFO'] == '') {
  header("Status: 303 Move!", true);
  header("Location: " . $_SERVER['PHP_SELF'] . "/", true);
  exit;
}

function header_cb($proxy, $h) {
  header($h);
  return strlen($h);
}

$proxy = curl_init();
curl_setopt($proxy, CURLOPT_URL, $darkstat . $_SERVER['PATH_INFO']);
curl_setopt($proxy, CURLOPT_HEADERFUNCTION, 'header_cb'); 
curl_exec($proxy);
curl_close($proxy);
