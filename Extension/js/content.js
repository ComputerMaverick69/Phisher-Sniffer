// // content.js

// chrome.runtime.onMessage.addListener(
//   function(request, sender, sendResponse) {
//     if( request.message === "fetch_top_domains" ) {
//       var urlHash = {}, links = document.links;
//       for(var i=0; i<links.length; i++) {
//         var domain = links[i].href.split('/')[2]
//         if (urlHash[domain]) {
//           urlHash[domain] = urlHash[domain] + 1;
//         }
//         else {
//           urlHash[domain] = 1;
//         }
//       }
//       chrome.runtime.sendMessage({"message": "all_urls_fetched", "data": urlHash});
//     }
//   }
// );

var testdata;
var prediction;

function predict(data, weight) {
  var f = 0;
  weight = [
    3.33346292e-1,
    -1.11200396e-1,
    -7.77821806e-1,
    1.1105859e-1,
    3.89430647e-1,
    1.99992062,
    4.44366975e-1,
    -2.77951957e-1,
    -6.00531647e-5,
    3.33200243e-1,
    2.66644002,
    6.66735991e-1,
    5.55496098e-1,
    5.57022408e-2,
    2.22225591e-1,
    -1.66678858e-1,
  ];
  for (var j = 0; j < data.length; j++) {
    f += data[j] * weight[j];
  }
  return f > 0 ? 1 : -1;
}

function isIPInURL(){
  var url = window.location.href
  try {
    var regex =  new RegExp("\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}");
    isValid = regex.test(url)

    if(isValid == true) {
      console.log("Phishing Website Detected!!!");
      return -1;
    } else {
      console.log("Legitimate Website Detected!!!");
      return 1;
    }
  } catch(e) {
    isValid = false;
  }
}

function isLongURL(){
  var url = window.location.href;    
  if(url.length<54){
    console.log("Legitimate Website Detected!!!");
    return 1;
  } else if(url.length>=54 && url.length<=75) {
    console.log("Suspicious Website Detected!!!");
    return 0;
  } else {
    console.log("Phishing Website Detected!!!");
    return -1;
  }
}

function isTinyURL() {
  var url = window.location.href;
  if(url.length > 100) {
    console.log("Legitimate Website Detected!!!");
    return 1;
  } else {
    console.log("Phishing Website Detected!!!");
    return -1;
  }
}

function isAlphaNumericURL() {
  var search = "@";
  var url = window.location.href;
  if(url.match(search) == null) {
    console.log("Legitimate Website Detected!!!")
    return 1;
  } else {
    console.log("Phishing Website Detected!!!");
    return -1;
  }
}

function isRedirectingURL() {
  var regex_1 = new RegExp("^http:");
  var regex_2 = new RegExp("^https:");

  var search = "//";
  var url = window.location.href;
  if(url.search(search) == 5 && regex_1.test == false && (url.substring(7)).match(search) == null) {
    console.log("Legitimate Website Detected!!!");
    return 1;
  } else if(url.search(search) == 6 && regex_2.test == false && (url.substring(8)).match(search) == null) {
    console.log("Legitimate Website Detected!!!");
    return 1;
  } else {
    console.log("Phishing Website Detected!!!");
    return -1;
  }
}

testdata = [isIPInURL(), isLongURL(), isTinyURL(), isAlphaNumericURL(), isRedirectingURL()];
prediction = predict(testdata);
chrome.extension.sendRequest(prediction);