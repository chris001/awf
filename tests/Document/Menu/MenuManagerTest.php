<?php
/**
 * @package		awf
 * @copyright	2014 Nicholas K. Dionysopoulos / Akeeba Ltd 
 * @license		GNU GPL version 3 or later
 */

namespace Awf\Tests\Document\Menu;

use Awf\Application\Application;
use Awf\Document\Menu\Item;
use Awf\Document\Menu\MenuManager;
use Awf\Tests\Helpers\ReflectionHelper;
use Awf\Text\Text;

/**
 * Class MenuManagerTest
 *
 * @package Awf\Tests\Document\Menu
 *
 * @coversDefaultClass \Awf\Document\Menu\MenuManager
 */
class MenuManagerTest extends \Awf\Tests\Helpers\ApplicationTestCase
{
	/** @var  \Awf\Document\Menu\MenuManager */
	protected $manager;

	protected function setUp()
	{
		parent::setUp();

		$this->manager = new MenuManager(static::$container);
	}

	public function testConstruct()
	{
		$manager = new MenuManager(static::$container);

		// For the life of me, I don't understand why assertInstanceOf doesn't want to work here!!!!!
		$this->assertTrue($manager instanceof \Awf\Document\Menu\MenuManager);

		$this->assertEquals(static::$container, ReflectionHelper::getValue($manager, 'container'));
	}

	public function testInitialiseFromDirectory()
	{
		$app = Application::getInstance('Fakeapp');
		$path = $app->getContainer()->basePath . '/View';

		$this->manager->initialiseFromDirectory($path, true);

		$items = ReflectionHelper::getValue($this->manager, 'items');

		$this->assertGreaterThanOrEqual(4, count($items));
		$this->assertArrayHasKey('menudouble', $items);
		$this->assertArrayHasKey('include', $items);
		$this->assertArrayHasKey('other', $items);
		$this->assertArrayHasKey('menuunspecified', $items);
		$this->assertArrayNotHasKey('menuexclude', $items);

		$this->assertEquals(array('main', 'other'), $items['menudouble']->getShow());
		$this->assertEquals(array('main'), $items['include']->getShow());
		$this->assertEquals(array('main'), $items['menuunspecified']->getShow());
		$this->assertEquals(array('other'), $items['other']->getShow());

		$this->assertEquals(2, $items['menudouble']->getOrder());
		$this->assertEquals(1, $items['include']->getOrder());
		$this->assertEquals(1, $items['other']->getOrder());
		$this->assertEquals(0, $items['menuunspecified']->getOrder());

		$this->assertEquals('FAKEAPP_MENUINCLUDE_TITLE', $items['include']->getTitle());
	}

	public function testDisableMenuUsingFlashVariable()
	{
		ReflectionHelper::setValue($this->manager, 'menuEnabledStatus', array());
		$isEnabled = $this->manager->isEnabled('main');
		$menuEnabledStatus = ReflectionHelper::getValue($this->manager, 'menuEnabledStatus');
		$this->assertArrayHasKey('main', $menuEnabledStatus);
		$this->assertTrue($isEnabled);

		ReflectionHelper::setValue($this->manager, 'menuEnabledStatus', array());
		static::$container->segment->setFlash('menu.main.enabled', 0);
		$isEnabled = $this->manager->isEnabled('main');
		$menuEnabledStatus = ReflectionHelper::getValue($this->manager, 'menuEnabledStatus');
		$this->assertArrayHasKey('main', $menuEnabledStatus);
		$this->assertFalse($isEnabled);
	}

	public function testDisableMenuViaMethod()
	{
		ReflectionHelper::setValue($this->manager, 'menuEnabledStatus', array());
		$isEnabled = $this->manager->isEnabled('main');
		$menuEnabledStatus = ReflectionHelper::getValue($this->manager, 'menuEnabledStatus');
		$this->assertArrayHasKey('main', $menuEnabledStatus);
		$this->assertTrue($isEnabled);

		$this->manager->disableMenu('main');
		$isEnabled = $this->manager->isEnabled('main');
		$menuEnabledStatus = ReflectionHelper::getValue($this->manager, 'menuEnabledStatus');
		$this->assertArrayHasKey('main', $menuEnabledStatus);
		$this->assertFalse($isEnabled);
	}

	public function testEnableMenuAfterItWasDisabled()
	{
		ReflectionHelper::setValue($this->manager, 'menuEnabledStatus', array('main' => false));
		$isEnabled = $this->manager->isEnabled('main');
		$this->assertFalse($isEnabled);

		$this->manager->enableMenu('main');

		$isEnabled = $this->manager->isEnabled('main');
		$menuEnabledStatus = ReflectionHelper::getValue($this->manager, 'menuEnabledStatus');
		$this->assertArrayHasKey('main', $menuEnabledStatus);
		$this->assertTrue($isEnabled);
	}

	public function testAddItem()
	{
		$item1 = new Item(array('name' => 'item1', 'title' => 'Item 1'), static::$container);
		$item2 = new Item(array('name' => 'item2', 'title' => 'Item 2'), static::$container);
		$item3 = new Item(array('name' => 'item3', 'title' => 'Item 3'), static::$container);
		$item1b = new Item(array('name' => 'item1', 'title' => 'Replacement'), static::$container);

		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(0, $items);

		$this->manager->addItem($item1);
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayHasKey('item1', $items);
		$this->assertEquals($item1, $items['item1']);

		$this->manager->addItem($item1b);
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayHasKey('item1', $items);
		$this->assertEquals($item1b, $items['item1']);

		$this->manager->addItem($item2);
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(2, $items);
		$this->assertArrayHasKey('item2', $items);
		$this->assertEquals($item2, $items['item2']);

		$this->manager->addItem($item3);
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(3, $items);
		$this->assertArrayHasKey('item3', $items);
		$this->assertEquals($item3, $items['item3']);

		return $this->manager;
	}

	public function testAddItemFromDefinition()
	{
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(0, $items);

		$this->manager->addItemFromDefinition(array('name' => 'item1', 'title' => 'Item 1'));
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayHasKey('item1', $items);
		$this->assertEquals('Item 1', $items['item1']->getTitle());

		$this->manager->addItemFromDefinition(array('name' => 'item1', 'title' => 'Item 1 new'));
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayHasKey('item1', $items);
		$this->assertEquals('Item 1 new', $items['item1']->getTitle());

		$this->manager->addItemFromDefinition(array('name' => 'item2', 'title' => 'Item 2'));
		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertCount(2, $items);
		$this->assertArrayHasKey('item2', $items);
		$this->assertEquals('Item 2', $items['item2']->getTitle());

		return $this->manager;
	}

	/**
	 * @depends testAddItem
	 *
	 * @param $manager
	 */
	public function testRemoveItem($manager)
	{
		$item2 = new Item(array('name' => 'item2', 'title' => 'Item 2'), static::$container);
		$item3 = new Item(array('name' => 'item3', 'title' => 'Item 3'), static::$container);

		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(3, $items);

		$manager->removeItem($item2);
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(2, $items);
		$this->assertArrayNotHasKey('item2', $items);

		$manager->removeItem($item3);
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayNotHasKey('item3', $items);

		$manager->removeItem($item2);
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayNotHasKey('item2', $items);
		$this->assertArrayNotHasKey('item3', $items);
	}

	/**
	 * @depends testAddItemFromDefinition
	 *
	 * @param $manager
	 */
	public function testRemoveItemByName($manager)
	{
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(2, $items);

		$manager->removeItemByName('item1');
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(1, $items);
		$this->assertArrayNotHasKey('item1', $items);

		$manager->removeItemByName('item2');
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(0, $items);
		$this->assertArrayNotHasKey('item2', $items);

		$manager->removeItemByName('item1');
		$items = ReflectionHelper::getValue($manager, 'items');
		$this->assertCount(0, $items);
		$this->assertArrayNotHasKey('item1', $items);
		$this->assertArrayNotHasKey('item2', $items);
	}

	/**
	 * @depends testAddItem
	 */
	public function testFindItem(MenuManager $manager)
	{
		$item = $manager->findItem('item1');
		$this->assertEquals('item1', $item->getName());

		$this->setExpectedException('\\Exception', 'Menu item not found', 500);
		$item = $manager->findItem('iamnotthere');
	}

	public function testClear()
	{
		$item1 = new Item(array('name' => 'item1', 'title' => 'Item 1'), static::$container);
		$item2 = new Item(array('name' => 'item2', 'title' => 'Item 2'), static::$container);
		$item3 = new Item(array('name' => 'item3', 'title' => 'Item 3'), static::$container);
		$this->manager->addItem($item1);
		$this->manager->addItem($item2);
		$this->manager->addItem($item3);

		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertNotEmpty($items);

		$this->manager->clear();

		$items = ReflectionHelper::getValue($this->manager, 'items');
		$this->assertEmpty($items);
	}

	public function testGetMenuItems()
	{
		$item1 = new Item(array('name' => 'item1', 'title' => 'Item 1', 'show' => array('main', 'other'), 'group' => 'foo'), static::$container);
		$item1b = new Item(array('name' => 'item1b', 'title' => 'Item 1b', 'show' => array('main', 'other')), static::$container);
		$item2 = new Item(array('name' => 'item2', 'title' => 'Item 2', 'show' => array('main')), static::$container);
		$item3 = new Item(array('name' => 'item3', 'title' => 'Item 3', 'show' => array('other')), static::$container);
		$item3b = new Item(array('name' => 'item3b', 'title' => 'Item 3', 'show' => array('other'), 'group' => 'foo'), static::$container);

		$this->manager->clear();
		$this->manager->addItem($item1);
		$this->manager->addItem($item1b);
		$this->manager->addItem($item2);
		$this->manager->addItem($item3);
		$this->manager->addItem($item3b);

		$items = $this->manager->getMenuItems('main');
		$this->assertCount(3, $items->getChildren());

		$items = $this->manager->getMenuItems('main', 'foo');
		$this->assertCount(1, $items->getChildren());

		$items = $this->manager->getMenuItems('other');
		$this->assertCount(4, $items->getChildren());

		$items = $this->manager->getMenuItems('other', 'foo');
		$this->assertCount(2, $items->getChildren());
	}
}