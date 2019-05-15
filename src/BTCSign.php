<?php

namespace BTCec;

class BTCSign Extends \BitcoinPHP\BitcoinECDSA\BitcoinECDSA
{
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
