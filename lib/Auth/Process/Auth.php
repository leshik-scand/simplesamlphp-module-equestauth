<?php

namespace SimpleSAML\Module\equestauth\Auth\Process;

use GuzzleHttp\Client;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Utils\HTTP;

/**
 * @package SimpleSAMLphp
 */
class Auth extends ProcessingFilter
{
    const GRANT_TYPE = 'password';
    const ACTION = 'loginByHash';

    /** @var string */
    private $tokenUrl;
    /** @var string */
    private $hashUrl;
    /** @var string */
    private $loginUrl;
    /** @var string */
    private $clientId;
    /** @var string */
    private $clientSecret;
    /** @var string */
    private $username;
    /** @var string */
    private $password;
    /** @var Client */
    private $httpClient;

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert(is_array($config));

        if (array_key_exists('tokenUrl', $config)) {
            $this->tokenUrl = $config['tokenUrl'];
        }
        if (array_key_exists('hashUrl', $config)) {
            $this->hashUrl = $config['hashUrl'];
        }
        if (array_key_exists('loginUrl', $config)) {
            $this->loginUrl = $config['loginUrl'];
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
        $this->httpClient = new Client();
    }

    /** @param array $request */
    public function process(&$request)
    {
        assert(is_array($request));
        assert(array_key_exists('Attributes', $request));
        $userEmail = $request['Attributes']['email'][0];

        HTTP::redirectTrustedURL($this->loginUrl, [
            'action' => self::ACTION,
            'uid' => $this->getUserHash($this->getAccessToken(), $userEmail)
        ]);
    }

    /**
     * @param string $accessToken
     * @param string $userEmail
     * @return string
     */
    private function getUserHash($accessToken, $userEmail)
    {
        assert(!empty($accessToken));
        assert(!empty($userEmail));

        $response = $this->httpClient->post($this->hashUrl, [
            'query' => ['email' => $userEmail],
            'headers' => [
                "Authorization" => "Bearer " . $accessToken
            ]
        ]);
        $responseArray = json_decode($response->getBody()->getContents(), true);
        return (json_last_error() == JSON_ERROR_NONE && isset($responseArray['uid']))
            ? $responseArray['uid']
            : "";
    }

    /** @return string */
    private function getAccessToken()
    {
        $response = $this->httpClient->post($this->tokenUrl, [
            'form_params' => [
                'grant_type' => self::GRANT_TYPE,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'username' => $this->username,
                'password' => $this->password,
            ]
        ]);

        $responseArray = json_decode($response->getBody()->getContents(), true);
        return (json_last_error() == JSON_ERROR_NONE && isset($responseArray['access_token']))
            ? $responseArray['access_token']
            : "";
    }
}
