<?php

namespace BTCec;

class BTCSign Extends \BitcoinPHP\BitcoinECDSA\BitcoinECDSA
{
    public function pubKeyFromSign(
        $encodedSignature,
        $message,
        $extrastr = "\x18Bitcoin Signed Message:\n")
    {
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
