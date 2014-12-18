<?php
/**
 * @package     Awf
 * @copyright   2014 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license     GNU GPL version 3 or later
 */

namespace Awf\Utils;

/**
 * IP address helper
 *
 * Makes sure that we get the real IP of the user
 */
class Ip
{
	/**
	 * Gets the visitor's IP address. Automatically handles reverse proxies
	 * reporting the IPs of intermediate devices, like load balancers. Examples:
	 * https://www.akeebabackup.com/support/admin-tools/13743-double-ip-adresses-in-security-exception-log-warnings.html
	 * http://stackoverflow.com/questions/2422395/why-is-request-envremote-addr-returning-two-ips
	 * The solution used is assuming that the last IP address is the external one.
	 *
	 * @return  string
	 */
	public static function getUserIP()
	{
		$ip = self::_real_getUserIP();
		$ip = trim($ip);
		return $ip;
	}

	/**
	 * Gets the visitor's IP address
	 *
	 * @return  string
	 */
	private static function _real_getUserIP()
	{
		return _real_getUserIP_helper();
	}

	private static function _real_getUserIP_helper()
	{
		$ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
		$getenv_exists = function_exists('getenv');
		$server_exists = ( (isset($_SERVER)) && !(empty($_SERVER)) );
		foreach ($ip_keys as $key) {
			$possible_ips = '';
			if ( ($server_exists) && (array_key_exists($key, $_SERVER) === true)  ) {
				$possible_ips = $_SERVER[$key];
			}
			elseif ($getenv_exists) {
				$possible_ips = getenv($key);
			}
			if ((strstr($possible_ips, ',') !== false) || (strstr($possible_ips, ' ') !== false)) {
				$possible_ips = str_replace(' ', ',', $possible_ips);
				$possible_ips = str_replace(',,', ',', $possible_ips);
			}
			foreach (explode(',', $possible_ips) as $ip) {
			// trim for safety measures
				$ip = trim($ip);
				// attempt to validate IP
				if (validate_ip($ip)) {
					return $ip;
				}
			}
		}
		return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
	}

	/**
	 * Ensures an ip address is both a valid IP and does not fall within
	 * a private network range.
	 */
	private static function validate_ip($ip)
	{
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
			return false;
		}
		return true;
	}


	/**
	 * Works around the REMOTE_ADDR not containing the user's IP
	 *
	 * @return  void
	 */
	public static function workaroundIPIssues()
	{
		$ip = self::getUserIP();

		if (isset($_SERVER) && ($_SERVER['REMOTE_ADDR'] == $ip))
		{
			return;
		}
		elseif(!isset($_SERVER) && function_exists('getenv') && (getenv('REMOTE_ADDR') == $ip))
		{
			return;
		}

		if (isset($_SERVER) && array_key_exists('REMOTE_ADDR', $_SERVER))
		{
			$_SERVER['AWF_REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'];
		}
		elseif (function_exists('getenv'))
		{
			if (getenv('REMOTE_ADDR'))
			{
				$_SERVER['AWF_REMOTE_ADDR'] = getenv('REMOTE_ADDR');
			}
		}

		global $_SERVER;
		$_SERVER['REMOTE_ADDR'] = $ip;

		if (function_exists('putenv'))
		{
			putenv("REMOTE_ADDR=$ip");
		}
	}
}
