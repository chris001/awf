<?php
/**
 * @package		awf
 * @copyright	2014 Nicholas K. Dionysopoulos / Akeeba Ltd 
 * @license		GNU GPL version 3 or later
 */

namespace Awf\Tests\Document;

use Awf\Application\Application;
use Awf\Document\Document;
use Awf\Document\Html;
use Awf\Tests\Helpers\ReflectionHelper;
use Awf\Tests\Stubs\Fakeapp\Container as FakeContainer;

/**
 * @package Awf\Tests\Document
 *
 * @coversDefaultClass \Awf\Document\Html
 */
class HtmlTest extends \Awf\Tests\Helpers\ApplicationTestCase
{
	public function testRenderHtml()
	{
		$document = Document::getInstance('html', static::$container);
		$document->getApplication()->setTemplate('nada');
		$this->assertInstanceOf('\\Awf\\Document\\Html', $document);
		$document->render();

		$contentType = $document->getHTTPHeader('Content-Type');
		$this->assertEquals('text/html', $contentType);

		$contentDisposition = $document->getHTTPHeader('Content-Disposition');
		$this->assertNull($contentDisposition);

		return $document;
	}

	public function testRenderAttachment()
	{
		$document = Document::getInstance('html', static::$container);
		$document->getApplication()->setTemplate('nada');
		$this->assertInstanceOf('\\Awf\\Document\\Html', $document);
		$document->setMimeType('application/pdf');
		$document->setName('foobar.pdf');
		$document->render();

		$contentType = $document->getHTTPHeader('Content-Type');
		$this->assertEquals('application/pdf', $contentType);

		$contentDisposition = $document->getHTTPHeader('Content-Disposition');
		$this->assertEquals('attachment; filename="foobar.pdf.html"', $contentDisposition);
	}
}
 