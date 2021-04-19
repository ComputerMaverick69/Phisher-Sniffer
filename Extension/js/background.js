// chrome.runtime.onMessage.addListener(
//   function(request, sender, sendResponse) {
//     if( request.message === "open_max_url" ) {
//       fullURL = "http://" + request.url;
//       chrome.tabs.create({"url": fullURL, "active": false});
//     }
//   }
// );

chrome.extension.onRequest.addListener(function(prediction){
  if (prediction == 1){
      alert("Info: This is a Legitimate Website!");
  } else if(prediction == 0) {
    alert("Warning: This is a Suspicious Website!!!")
  }
  else if (prediction == -1){
    alert("Danger: This is a Phishing Website. Exit Immediately!");
  }
});
