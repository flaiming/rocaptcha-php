<html>
  <body>
    <form action="" method="post">
<?php

require_once('rocaptchalib.php');

$publickey = "f636349fa11ca68ed267923451827a";
$privatekey = "922c737fc977e60fb70d6002b2d6d7";

# the response from RoCATPCHA
$resp = null;
# the error code from RoCATPCHA, if any
$error = null;

# was there a RoCATPCHA response?
if (isset($_POST["rocaptcha_response_field"])) {
        $resp = RoCaptcha::checkAnswer($privatekey,
                                        $_POST["rocaptcha_challenge_field"],
                                        $_POST["rocaptcha_response_field"],
										$_POST["rocaptcha_session_id"]);

        if ($resp->is_valid) {
                echo "Passed!";
        } else {
                # set the error code so that we can display it
                $error = $resp->error;
				echo "Please try again.";
        }
}
echo RoCaptcha::getHtml($publickey, $error, 'cs');
?>
    <br />
    <input type="submit" value="submit" />
    </form>
  </body>
</html>
