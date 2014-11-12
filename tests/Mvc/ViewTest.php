<?php
/**
 * @package        awf
 * @copyright      2014 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license        GNU GPL version 3 or later
 */

namespace Awf\Tests\View;

use Awf\Tests\Helpers\ReflectionHelper;
use Awf\Tests\Stubs\Fakeapp\Container;
use Awf\Tests\Stubs\Mvc\ViewStub;

require_once 'ViewDataprovider.php';

class ViewTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @group           View
     * @group           ViewEscape
     * @covers          View::escape
     */
    public function testEscape()
    {
        $view = new ViewStub();
        $escape = $view->escape('<>àè?"\'');

        $this->assertEquals("&lt;&gt;àè?&quot;'", $escape, 'View::escape Failed to escape the string');
    }
}
