/*
 * Version: 2.1.2
 */

// Notify Plugin - Code for the demo site of HtmlCoder
// You can delete the code below
//-----------------------------------------------
(function($) {

	"use strict";

	$(document).ready(function() {
		console.log("Document Ready!");

/*
		$(document).on({
			ajaxStart: function() { $("body").addClass("page-loader-1"); },
	    	ajaxStop: function() { $("body").removeClass("page-loader-1"); }
		});
*/
		$("#loginButton").on("click", loginClickHandler);

		if (($(".main-navigation.onclick").length>0) && $(window).width() > 991 ){
			$.notify({
				// options
				message: 'The Dropdowns of the Main Menu, are now open with click on Parent Items. Click "Home" to checkout this behavior.'
			},{
				// settings
				type: 'info',
				delay: 10000,
				offset : {
					y: 150,
					x: 20
				}
			});
		};
		if (!($(".main-navigation.animated").length>0) && $(window).width() > 991 && $(".main-navigation").length>0){
			$.notify({
				// options
				message: 'The animations of main menu are disabled.'
			},{
				// settings
				type: 'info',
				delay: 10000,
				offset : {
					y: 150,
					x: 20
				}
			}); // End Notify Plugin - The above code (from line 14) is used for demonstration purposes only

		};
	}); // End document ready

})(jQuery);


function loginClickHandler() {
	console.log("loginClickHandler()");

	//TODO: Display Spinner
	$("body").addClass("page-loader-2");

	$.ajax({
        url: "/login",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify({"username": $("#username").val(), "password": $("#password").val()}),
        success: data => {
            console.log(data);
            var authResponseJson = JSON.parse(data);

            if(authResponseJson.success) {
				location.href = authResponseJson.redirectUrl;
            } else {
            	//TODO: use modal popup
            	$("body").removeClass("page-loader-2");
            	alert(authResponseJson.errorMessage);
            }
        }
    });
}

window.paceOptions = {
  // Disable the 'elements' source
  elements: false,
  document: true,

}