<html>
  <body>
    <form action="" method="post">
<?php

require_once('rocaptchalib.php');

$publickey = "49c47baecc3738a36bb99665e290fc";
$privatekey = "e5b725f71537ec50ceee5c6a9b27d6";

# the response from reCAPTCHA
$resp = null;
# the error code from reCAPTCHA, if any
$error = null;

# was there a reCAPTCHA response?
if (isset($_POST["rocaptcha_response_field"])) {
        $resp = RoCaptcha::checkAnswer($privatekey,
                                        $_SERVER["REMOTE_ADDR"],
                                        $_POST["rocaptcha_challenge_field"],
                                        $_POST["rocaptcha_response_field"]);

        if ($resp->is_valid) {
                echo "You got it!";
        } else {
                # set the error code so that we can display it
                $error = $resp->error;
				echo "WRONG";
        }
}
echo RoCaptcha::getHtml($publickey, $error, 'cs');
?>
    <br/>
    <input type="submit" value="submit" />
    </form>
  </body>
</html>
