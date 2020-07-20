<?php

namespace SimpleSAML\Module\equestauth\Auth\Process;

use \DateInterval;
use \DateTime;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error;
use SimpleSAML\Memcache;
use SimpleSAML\Utils\HTTP;

/**
 * @package SimpleSAMLphp
 */
class Auth extends ProcessingFilter
{
    const GRANT_TYPE = 'password';

    /** @var string */
    private $tokenUrl;
    /** @var string */
    private $apiUrl;
    /** @var string */
    private $clientId;
    /** @var string */
    private $clientSecret;
    /** @var string */
    private $username;
    /** @var string */
    private $password;

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert(is_array($config));

        if (array_key_exists('tokenUrl', $config)) {
            $this->tokenUrl = $config['tokenUrl'];
        }
        if (array_key_exists('apiUrl', $config)) {
            $this->apiUrl = $config['apiUrl'];
        }
        if (array_key_exists('clientId', $config)) {
            $this->clientId = $config['clientId'];
        }
        if (array_key_exists('clientSecret', $config)) {
            $this->clientSecret = $config['clientSecret'];
        }
        if (array_key_exists('username', $config)) {
            $this->username = $config['username'];
        }
        if (array_key_exists('password', $config)) {
            $this->password = $config['password'];
        }
    }

    /** @param array $request */
    public function process(&$request)
    {
        assert(is_array($request));
        assert(array_key_exists('Attributes', $request));
        $userEmail = $request['Attributes']['email'][0];

        $responseArray = $this->getTokenDataByPassword();

        $this->authUserByEmailInAdminPanel($this->getAuthHeaderFromResponseArray($responseArray), $userEmail);
    }

    /** @return array */
    private function getTokenDataByPassword()
    {
        $curl = curl_init();
        $content = "grant_type=" . self::GRANT_TYPE . "&client_id=$this->clientId&client_secret=$this->clientSecret"
            . "&username=$this->username&password=$this->password";

        curl_setopt_array($curl, [
            CURLOPT_URL => $this->tokenUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $content
        ]);
        $response = curl_exec($curl);
        curl_close($curl);

        $responseArray = json_decode($response, true);
        if (json_last_error() == JSON_ERROR_NONE) {
            return $responseArray;
        }
        return [];
    }

    /**
     * @param string $authHeader
     * @param string $userEmail
     */
    private function authUserByEmailInAdminPanel($authHeader, $userEmail)
    {
        $apiUrl = $this->apiUrl . "?email=$userEmail";

        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $apiUrl,
            CURLOPT_HTTPHEADER => [$authHeader],
            //CURLOPT_AUTOREFERER => true,
            //CURLOPT_FOLLOWLOCATION => true,
            //CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEFILE => ''
        ]);
        curl_exec($curl);
        curl_close($curl);
    }

    /**
     * @param array $responseArray
     * @return string
     */
    private function getAuthHeaderFromResponseArray($responseArray)
    {
        $accessToken = $responseArray['access_token'];
        $tokenType = $responseArray['token_type'];
        return "Authorization: $tokenType $accessToken";
    }
}
