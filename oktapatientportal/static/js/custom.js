/*
 * Version: 2.1.2
 */

$(document).ready(function() {
	console.log("Document Ready!");

	$("#loginButton").on("click", loginClickHandler);
	$("#acceptConsent").on("click", acceptConsentClickHandler);
	$("#rejectConsent").on("click", rejectConsentClickHandler);
	$("#signUpButton").on("click", signUpButtonClickHandler);
	$("#customSignUpButton").on("click", signUpButtonClickHandler);
	$("#registerUser").on("click", registerUserClickHandler);
	$("#submitRegistrationDefault").on("click", submitRegistrationDefaultClickHandler);
	$("#submitRegistrationAlt1").on("click", submitRegistrationAlt1ClickHandler);
	$("#verifyAccount").on("click", verifyAccountClickHandler);
	$("#setPreRegCredentials").on("click", setPreRegCredentialsClickHandler);

	$("#password").keypress(function (e) {
		var key = e.which;
		if(key == 13) {  // the enter key code
			$("#loginButton").click();
			return false;
		}
	});

	$("#registrationConfirmPassword").keypress(function (e) {
		var key = e.which;
		if(key == 13) {  // the enter key code
			$("#registerUser").click();
			return false;
		}
	});

	//Display Modals
	console.log("stateToken: " + $("#stateToken").val());
	if($("#showConsent").val() == "True") {
		$("#consentModal").modal("show");
	}else if($("#showRegistrationDefault").val() == "True") {
	    $("#registrationDefaultModal").modal("show");
	} else if($("#showRegistrationAlt1").val() == "True") {
	    $("#registrationAlt1Modal").modal("show");
	} else if($("#stateToken").val() != "") {
	    $("#verifyAccountModal").modal("show");
	}

}); // End document ready

function signUpButtonClickHandler() {
    console.log("signUpButtonClickHandler()");

    $("#basicRegistrationModal").modal("show");

}

function loginClickHandler() {
	console.log("loginClickHandler()");

	var url = "/login";

	if($("#sessionId").val()) {
	    url = "/login/" + $("#sessionId").val();
	}

	oktaSignIn.session.get(function (res) {
      // Session exists, show logged in state.
      if (res.status === 'ACTIVE') {
        // showApp()
        console.log("Session Active");
        oktaSignIn.session.close(function (err) {
          if (err) {
            // The user has not been logged out, perform some error handling here.
            console.log("Failed to close the session (if it exsists) otherwise fine");
            console.log(err);
          }
          // The user is now logged out.
            callLogin(url);
        });
      } else if (res.status === 'INACTIVE') {
        console.log("Session Not Active");
        callLogin(url);
      }
	});
}

function callLogin(url) {
    $.ajax({
        url: url,
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
            	if($("#showRegistrationDefault").val() == "True") {
            	    $("#registrationDefaultModal").modal("show");
            	} else if($("#showRegistrationAlt1").val() == "True") {
            	    $("#registrationAlt1Modal").modal("show");
            	}
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
	window.location.href = "/logout";
}

function registerUserClickHandler() {
    console.log("registerUserClickHandler()");

    var isValid = true;
    var errorMessage = "";

    if($("#registraionEmail").val() == "") {
        isValid = false;
        errorMessage += "Email is Required\r\n";
    }

    if($("#registrationPassword").val() == "") {
        isValid = false;
        errorMessage += "Password is Required\r\n";
    }

    if($("#registrationPassword").val() != $("#registrationConfirmPassword").val()) {
        isValid = false;
        errorMessage += "Passwords must match\r\n";
    }

    if(isValid) {
        $("#registerUser").prop("disabled", true);
    	$("#registerUser").html(
    	    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>Processing...'
    	);

    	oktaSignIn.session.get(function (res) {
          // Session exists, show logged in state.
          if (res.status === 'ACTIVE') {
            // showApp()
            console.log("Session Active");
            oktaSignIn.session.close(function (err) {
              if (err) {
                // The user has not been logged out, perform some error handling here.
                console.log("Failed to close the session (if it exsists) otherwise fine");
                console.log(err);
              }
              // The user is now logged out.
                invokeRegisterBasic()
            });
          } else if (res.status === 'INACTIVE') {
            console.log("Session Not Active");
            invokeRegisterBasic();
          }
    	});
    } else {
        alert(errorMessage);
    }
}

function invokeRegisterBasic() {
    $.ajax({
        url: "/register-basic",
        type: "POST",
        data: JSON.stringify({"username": $("#registraionEmail").val(), "password": $("#registrationPassword").val()}),
        contentType: "application/json; charset=utf-8",
        success: data => {
            console.log(data);
            var acceptConsentResponseJson = JSON.parse(data);

            if(acceptConsentResponseJson.success) {
            	$("#basicRegistrationModal").modal("hide");
            	$("#basicRegistrationCompleteModal").modal("show");
            } else {
            	//TODO: use modal popup
            	errorMessage = acceptConsentResponseJson.errorMessage + "\r\n";

            	if(acceptConsentResponseJson.errorMessages != undefined){
            	    for(msgIdx in acceptConsentResponseJson.errorMessages) {
            	        errorMessage += acceptConsentResponseJson.errorMessages[msgIdx].errorMessage + "\r\n";
            	        if(acceptConsentResponseJson.errorMessages[msgIdx].errorMessage == "login: An object with this field already exists in the current organization") {
            	            $("#basicRegistrationModal").modal("hide");
            	            $("#popupLoginModal").modal("show");
            	            return;
            	        }
            	    }
            	}

            	alert(errorMessage);
            }
            $("#registerUser").prop("disabled", false);
        	$("#registerUser").html("Sign Me Up!");
        }
    });
}

function submitRegistrationDefaultClickHandler(){
    console.log("submitRegistrationDefaultClickHandler()");

    var isValid = true;
    var errorMessage = "";

    if($("#regDefaultFirstName").val() == "") {
        isValid = false;
        errorMessage += "First Name is Required\r\n";
    }

    if($("#regDefaultLastName").val() == "") {
        isValid = false;
        errorMessage += "Last Name is Required\r\n";
    }

    if($("#regDefaultHeight").val() == "") {
        isValid = false;
        errorMessage += "Height is Required\r\n";
    }

    if($("#regDefaultWeight").val() == "") {
        isValid = false;
        errorMessage += "Weight is Required\r\n";
    }

    if(isValid) {
        $("#submitRegistrationDefault").prop("disabled", true);
    	$("#submitRegistrationDefault").html(
    	    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>Processing...'
    	);
    	var json_post_data = {
    	    "firstName": $("#regDefaultFirstName").val(),
    	    "lastName": $("#regDefaultLastName").val(),
    	    "height": $("#regDefaultHeight").val(),
    	    "weight": $("#regDefaultWeight").val()
    	}
        $.ajax({
            url: "/register-default",
            type: "POST",
            data: JSON.stringify(json_post_data),
            contentType: "application/json; charset=utf-8",
            success: data => {
                console.log(data);
                var responseJson = JSON.parse(data);

                if(responseJson.success) {
                	$("#userNameLabel").html(responseJson.user.profile.firstName + " " + responseJson.user.profile.lastName);
                	$("#registrationDefaultModal").modal("hide");
                	$("#finalRegistrationCompleteModal").modal("show");
                } else {
                	//TODO: use modal popup
                	errorMessage = responseJson.errorMessage + "\r\n";

                	if(responseJson.errorMessages != undefined){
                	    for(msgIdx in responseJson.errorMessages) {
                	        errorMessage += responseJson.errorMessages[msgIdx].errorMessage + "\r\n";
                	    }
                	}

                	alert(errorMessage);
                }
                $("#submitRegistrationDefault").prop("disabled", false);
            	$("#submitRegistrationDefault").html("Save");
            }
        });
    } else {
        alert(errorMessage);
    }
}

function submitRegistrationAlt1ClickHandler() {
    console.log("submitRegistrationAlt1()");

    var isValid = true;
    var errorMessage = "";

    if($("#regAlt1FirstName").val() == "") {
        isValid = false;
        errorMessage += "First Name is Required\r\n";
    }

    if($("#regAlt1LastName").val() == "") {
        isValid = false;
        errorMessage += "Last Name is Required\r\n";
    }

    if($("#regAlt1DOB").val() == "") {
        isValid = false;
        errorMessage += "Date of Birth is Required\r\n";
    }

    if($("#regAlt1MobileNumber").val() == "") {
        isValid = false;
        errorMessage += "Mobile Number is Required\r\n";
    }

    if(isValid) {
        $("#submitRegistrationAlt1").prop("disabled", true);
    	$("#submitRegistrationAlt1").html(
    	    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>Processing...'
    	);
    	var json_post_data = {
    	    "firstName": $("#regAlt1FirstName").val(),
    	    "lastName": $("#regAlt1LastName").val(),
    	    "dob": $("#regAlt1DOB").val(),
    	    "mobilePhone": $("#regAlt1MobileNumber").val()
    	}
        $.ajax({
            url: "/register-alt1",
            type: "POST",
            data: JSON.stringify(json_post_data),
            contentType: "application/json; charset=utf-8",
            success: data => {
                console.log(data);
                var responseJson = JSON.parse(data);

                if(responseJson.success) {
                	$("#userNameLabel").html(responseJson.user.profile.firstName + " " + responseJson.user.profile.lastName);
                	$("#registrationAlt1Modal").modal("hide");
                	$("#finalRegistrationCompleteModal").modal("show");
                } else {
                	//TODO: use modal popup
                	errorMessage = responseJson.errorMessage + "\r\n";

                	if(responseJson.errorMessages != undefined){
                	    for(msgIdx in responseJson.errorMessages) {
                	        errorMessage += responseJson.errorMessages[msgIdx].errorMessage + "\r\n";
                	    }
                	}

                	alert(errorMessage);
                }
                $("#submitRegistrationAlt1").prop("disabled", false);
            	$("#submitRegistrationAlt1").html("Save");
            }
        });
    } else {
        alert(errorMessage);
    }
}

function verifyAccountClickHandler() {
    console.log("verifyAccountClickHandler()");

	var isValid = true;
    var errorMessage = "";

    if($("#verifyDOB").val() == "") {
        isValid = false;
        errorMessage += "Dateof Brith is Required\r\n";
    }

    if(isValid) {
        $("#verifyAccount").prop("disabled", true);
    	$("#verifyAccount").html(
    	    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>Processing...'
    	);

    	var json_post_data = {
    	    "dob": $("#verifyDOB").val(),
    	    "stateToken": $("#stateToken").val()
    	}

        $.ajax({
            url: "/verify-dob",
            type: "POST",
            data: JSON.stringify(json_post_data),
            contentType: "application/json; charset=utf-8",
            success: data => {
                console.log(data);
                var responseJson = JSON.parse(data);

                if(responseJson.success) {
                	$("#verifyAccountModal").modal("hide");
                	$("#lblUserNamePreRegform").html(responseJson.user.profile.email);
                	$("#registrationPreRegModal").modal("show");
                } else {
                	//TODO: use modal popup
                	errorMessage = responseJson.errorMessage + "\r\n";

                	if(responseJson.errorMessages != undefined){
                	    for(msgIdx in responseJson.errorMessages) {
                	        errorMessage += responseJson.errorMessages[msgIdx].errorMessage + "\r\n";
                	    }
                	}

                	alert(errorMessage);
                }
                $("#verifyAccount").prop("disabled", false);
            	$("#verifyAccount").html("Verify");
            }
        });
    } else {
        alert(errorMessage);
    }
}

function setPreRegCredentialsClickHandler() {
    console.log("setPreRegCredentialsClickHandler()");

    var isValid = true;
    var errorMessage = "";

    if($("#preRegPassword").val() == "") {
        isValid = false;
        errorMessage += "Password is Required\r\n";
    }

    if($("#preRegPassword").val() != $("#preRegConfirmPassword").val()) {
        isValid = false;
        errorMessage += "Passwords must match\r\n";
    }

    if(isValid) {
        $("#setPreRegCredentials").prop("disabled", true);
    	$("#setPreRegCredentials").html(
    	    '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>Processing...'
    	);

    	var json_post_data = {
    	    "username": $("#lblUserNamePreRegform").html(),
    	    "newPassword": $("#preRegPassword").val(),
    	    "stateToken": $("#stateToken").val()
    	}

        $.ajax({
            url: "/pre-reg-password-set",
            type: "POST",
            data: JSON.stringify(json_post_data),
            contentType: "application/json; charset=utf-8",
            success: data => {
                console.log(data);
                var responseJson = JSON.parse(data);

                if(responseJson.success) {
                	$("#registrationPreRegModal").modal("hide");
                	$("#finalRegistrationCompleteModal").modal("show");
                	$("#finalRegistrationCompleteModalClose").on("click", () => { window.location.href=responseJson.redirectUrl })
                } else {
                	//TODO: use modal popup
                	errorMessage = responseJson.errorMessage + "\r\n";

                	if(responseJson.errorMessages != undefined){
                	    for(msgIdx in responseJson.errorMessages) {
                	        errorMessage += responseJson.errorMessages[msgIdx].errorMessage + "\r\n";
                	    }
                	}

                	alert(errorMessage);
                }
                $("#setPreRegCredentials").prop("disabled", false);
            	$("#setPreRegCredentials").html("Save");
            }
        });
    } else {
        alert(errorMessage);
    }
}