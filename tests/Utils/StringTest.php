<?php
/**
 * Created by PhpStorm.
 * User: Nicholas
 * Date: 6/6/2014
 * Time: 1:54 μμ
 */

namespace Awf\Tests\Utils;

use Awf\Utils\String;

class StringTest extends \PHPUnit_Framework_TestCase
{
	/**
	 * Test to slug method
	 *
	 * @dataProvider getTestToSlug
	 */
	public function testToSlug($word, $expect, $message)
	{
		$string = String::toSlug($word);
		$this->assertEquals(
			$expect,
			$string,
			$message
		);
	}

	public function getTestToSlug()
	{
		return array(
			array("foobar", "foobar", 'String foobar returns as is'),
			array("foo-bar", "foo-bar", 'Hypens should be left in place'),
			array("foo bar", "foo-bar", 'Spaces should be replaced with hypens'),
			array("foo*bar", "foobar", 'Non-alphanumeric should be removed'),
			array("foo&bar=foo", "fooabarfoo", 'Non-alphanumeric should be removed'),
			array("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv", 'Strings over 100 characters should be limited to 100'),
			array("Foobar", "foobar", 'Strings should be forced into lowercase'),
		);
	}

	/**
	 * Test to ASCII method
	 *
	 * @dataProvider getTestToASCII
	 */
	public function testToASCII($word, $expect, $message)
	{
		$string = String::toSlug($word);
		$this->assertEquals(
			$expect,
			$string,
			$message
		);
	}

	public function getTestToASCII()
	{
		return array(
			array("foobar", "foobar", 'String foobar returns as is'),
			array("foo-bar", "foo-bar", 'Hypens should be left in place'),
			array("foo bar", "foo-bar", 'Spaces should be replaced with hypens'),
			array("foo*bar", "foobar", 'Non-alphanumeric should be removed'),
			array("foo&bar=foo", "fooabarfoo", 'Non-alphanumeric should be removed'),
		);
	}

	public function getToBoolProvider()
	{
		return array(
			array('true', true),
			array('false', false),
			array('', false),
			array('0', false),
			array('1', true),
			array('any', true),
		);
	}

	/**
	 * Test the toBool method.
	 *
	 * @dataProvider getToBoolProvider
	 */
	public function testToBool($string, $expected)
	{
		$this->assertEquals($expected, String::toBool($string));
	}
}
 