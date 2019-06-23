/*
 * Version: 2.1.2
 */

$(document).ready(function() {
	console.log("Document Ready!");

	$("#loginButton").on("click", loginClickHandler);
	$("#acceptConsent").on("click", acceptConsentClickHandler);
	$("#rejectConsent").on("click", rejectConsentClickHandler);

	$("#password").keypress(function (e) {
		var key = e.which;
		if(key == 13) {  // the enter key code
			$("#loginButton").click();
			return false;
		}
	});

	//Display Modals
	if($("#showConsent").val() == "True") {
		$("#consentModal").modal("show");
	}

}); // End document ready



function loginClickHandler() {
	console.log("loginClickHandler()");

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
                Pace.stop();
            	//TODO: use modal popup
            	$("body").removeClass("page-loader-2");
            	alert(authResponseJson.errorMessage);
            }
        }
    });
}

function acceptConsentClickHandler() {
	console.log("acceptConsentClickHandler()");
	$(this).prop("disabled", true);
	$(this).html(
	    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>Processing...'
	);
	$.ajax({
        url: "/accept-consent",
        type: "POST",
        contentType: "application/json; charset=utf-8",
        success: data => {
            console.log(data);
            var acceptConsentResponseJson = JSON.parse(data);

            if(acceptConsentResponseJson.success) {
            	$("#consentModal").modal("hide");
            } else {
            	//TODO: use modal popup
            	$(this).prop("disabled", false);
            	$(this).html("I Accept");
            	alert(acceptConsentResponseJson.errorMessage);
            }
        }
    });

}

function rejectConsentClickHandler() {
	console.log("rejectConsentClickHandler()");
	Pace.show();
	window.location.href = "/logout";
}

