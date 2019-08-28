<?php

namespace BTCec;

class BTCSign Extends \BitcoinPHP\BitcoinECDSA\BitcoinECDSA
{
    public $rnd_fn; // callable random_bytes function

    /**
     * Analog of PHP7-function random_bytes($length)
     *
     * @param integer $len
     * @return string
     */
    public function genRandomBytes($len)
    {
        if ($len > 0) {
            return \call_user_func($this->rnd_fn, $len);
        }
    }

    public function __construct($private_key_file = '', $password_file = '', $cipher = "aes-256-ecb")
    {
        //check available function for quick-generation random bytes
        foreach ([
            '\random_bytes', //for PHP7
            '\openssl_random_pseudo_bytes', // for PHP5
        ] as $fn) {
            if (\function_exists($fn)) {
                $this->rnd_fn = $fn;
                break;
            }
        }
        if (empty($this->rnd_fn)) {
            throw new \Exception('Your system is not able to generate strong enough random numbers');
        }

        parent::__construct();

        if (!empty($private_key_file)) {
            $ret = $this->loadOrGenPrivateKey($private_key_file, $password_file, $cipher);
            if (is_string($ret)) {
                throw new \Exception($ret);
            }
        }
    }

    public function loadOrGenPrivateKey($private_key_file, $password_file, $cipher = "aes-256-ecb")
    {
        if (is_file($private_key_file)) {
            $ret = $this->loadPrivateKeyFromFile($private_key_file, $password_file, $cipher);
        } else {
            $ret = $this->generatePrivateKeyToFile($private_key_file, $password_file, $cipher);
        }
        return $ret;
    }

    public function loadPrivateKeyFromFile($private_key_file, $password_file, $cipher = "aes-256-ecb")
    {
        if (!is_file($password_file)) {
            return "Password file not found";
        }
        if (!is_file($private_key_file)) {
            return "Private_key file not found";
        }
        $password = @file_get_contents($password_file);
        if (strlen($password) != 64) {
            return "Bad password file length";
        }
        $password = @hex2bin($password);
        if (strlen($password) != 32) {
            return "Incorrect password file";
        }
        $encrypted = @file_get_contents($private_key_file);
        $decrypted = \openssl_decrypt($encrypted, $cipher, $password);
        if (!is_string($decrypted) || strlen($decrypted) != 64 || (strlen(hex2bin($decrypted)) != 32)) {
            return "Can't decrypt private key";
        }
        $this->k = $decrypted;
        return false;
    }

    public function generatePrivateKeyToFile($private_key_file, $password_file, $cipher = "aes-256-ecb")
    {
        if (!is_file($password_file)) {
            $password = bin2hex($this->genRandomBytes(32));
            if (!file_put_contents($password_file, $password)) {
                return "Can't write password file";
            }
        }
        $password = file_get_contents($password_file);
        if (strlen($password) != 64) {
            return "Bad password file length";
        }
        $password = @hex2bin($password);
        if (strlen($password) != 32) {
            return "Incorrect password file";
        }

        do {
            $res = bin2hex($this->genRandomBytes(32));
            $res = hash('sha256', $res . microtime(true) . $password);

        } while(gmp_cmp(gmp_init($res, 16), gmp_sub($this->n, gmp_init(1, 10))) === 1); // make sure the generate string is smaller than n

        $encrypted = \openssl_encrypt($res, $cipher, $password);
        file_put_contents($private_key_file, $encrypted);
        $encrypted = file_get_contents($private_key_file);
        $decrypted = \openssl_decrypt($encrypted, $cipher, $password);
        if ($decrypted != $res) {
            return "Error back-decryption private key";
        }
        $this->k = $res;
        return false;
    }

    public function geta160($pub_key = null)
    {
        if (is_null($pub_key)) {
            $pub_key = $this->getPubKey();
        }
        return hash('ripemd160', hex2bin($pub_key));
    }

    public function verifySign64a160(
        $message,
        $sign_64,
        $a_160,
        $extrastr = "\x18Bitcoin Signed Message:\n"
    ) {
        $derPub = $this->pubKeyFromSign64($sign_64, $message, $extrastr);
        if (strlen($derPub) != 66) {
            return false;
        }
        $r_160 = hash('ripemd160', hex2bin($derPub));
        return $a_160 === $r_160;
    }

    public function simpleSign64(
        $message,
        $priv_hex = null,
        $nonce = null,
        $extrastr = "\x18Bitcoin Signed Message:\n"
    ) {
        if (!is_null($priv_hex)) {
            $this->setPrivateKey($priv_hex);
        }
        $sign_hex = $this->signMsgHex($message, $nonce, $extrastr);

        return base64_encode(hex2bin($sign_hex));
    }

    public function signMsgHex(
        $message,
        $nonce = null,
        $extrastr = "\x18Bitcoin Signed Message:\n"
    ) {
        $hash = hash('sha256',
                    hash('sha256',
                        $extrastr . $this->numToVarIntString(strlen($message)) . $message,
                        true
                    )
                );

        $points = $this->getSignatureHashPoints($hash, $nonce);

        $R = $points['R'];
        $S = $points['S'];

        while(strlen($R) < 64)
            $R = '0' . $R;

        while(strlen($S) < 64)
            $S = '0' . $S;

        $finalFlag = 0;
        for($i = 0; $i < 4; $i++)
        {
            $flag = 31;
            $flag += $i;

            $pubKeyPts = $this->getPubKeyPoints();

            $recoveredPubKey = $this->getPubKeyWithRS($flag, $R, $S, $hash);

            if($this->getDerPubKeyWithPubKeyPoints($pubKeyPts, true) === $recoveredPubKey)
            {
                $finalFlag = $flag;
            }
        }

        if($finalFlag === 0)
        {
            throw new \Exception('Unable to get a valid signature flag.');
        }

        return dechex($finalFlag) . $R . $S;
    }

    public function pubKeyFromSign64(
        $encodedSignature,
        $message,
        $extrastr = "\x18Bitcoin Signed Message:\n"
    ) {
        $hash = hash('sha256', hash('sha256',
            $extrastr . $this->numToVarIntString(strlen($message)) . $message,
            true));

        $signature = base64_decode($encodedSignature);

        //check flag
        $flag = hexdec(bin2hex(substr($signature, 0, 1)));
        if($flag < 31 || $flag > 34) return false; // compressed only: 31,32,33,34

        $R = bin2hex(substr($signature, 1, 32));
        $S = bin2hex(substr($signature, 33, 32));

        return $this->getPubKeyWithRS($flag, $R, $S, $hash);
    }
}
