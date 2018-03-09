# Access Control for use in Laravel Middleware

The AccessManager abstract class uses an "access matrix" to determine whether a user with a particular 'role' can perform an action. It is based on route names and depends on a specific but common route naming style. Although Laravel has [authorization policiy support built-in](https://laravel.com/docs/5.6/authorization#creating-policies), I prefer to have policies together in one place, as opposed to one-class-per-policy under a policies folder.

Using the AccessManager, permissions for a set of resources such as 'accounts' and 'widgets' can be defined inside a 'matrix' (array) like follows:

```php
$matrix = [

    // ---Accounts ---

    'api.accounts.*'=>[
        'manager'=>true,
        'staff'=>true,
    ],
    'api.accounts.destroy'=>[
        'staff'=>false,
    ],


    // --- Widgets ---

    'api.widgets.index'=>[
        'manager'=>true,
        'staff'=>true,
    ],
    'api.widgets.update'=>[
        'staff'=>function($user,$routeParams,$queryParams) { // delegate as closure
            $widget = Widget::findOrFail($routeParams['widget']);
            $isAllowed =  ($widget instanceof Ownable) ?  $widget->isOwnedBy() : false;
            return $isAllowed;
        },
    ],
];
```

In the example above, a user can have one or more of the following roles: 'manager', 'staff'.

For accounts, users with either the manager of the staff role have permission for routes that match the 'wildcard', for example 'api.accounts.index'. However, only managers can delete (destroy) an account. The more-specific role will override the wildcard, but only if a role has a permission override specifically listed (which is why managers are granted destroy access).

For widgets, both roles are allowed 'index' access (eg, to view a list of widgets). However, a staff role can only update a widget if it 'owns' the widget. Ownership is determined by a closure, which can delegate the ownership logic to the model (as shown), or implement the logic inline inside the closure itself.

## Usage:

1. extend base class AccessManager...

2. Implement :

    abstract protected function accessMatrix()

3. Optional: override to set super admin roles:

```php
protected function setSuperadminRoles();
{
    $this->_superadminRoles = ['super-admin'];
}
```

Route names must be in format:

    {prefix}.{resource}.{action}
    api.widgets.show

## Example:

```php
use PsgcLaravelPackages\AccessControl\AccessManager;

class CheckSiteRole extends AccessManager
{

    protected function accessMatrix() {
        return [
            'api.accounts.*'=>[
                'manager'=>true,
                'staff'=>true,
            ],
            'api.accounts.destroy'=>[
                'staff'=>false,
            ],
            'api.widgets.index'=>[
                'manager'=>true,
                'staff'=>true,
            ],
            'api.widgets.update'=>[
                'staff'=>function($user,$routeParams,$queryParams) { // delegate as closure
                    $widget = Widget::findOrFail($routeParams['widget']);
                    $isAllowed =  ($widget instanceof Ownable) ?  $widget->isOwnedBy() : false;
                    return $isAllowed;
                },
            ]
        ];
    }
```

Edit app/Http/Kernel.php to update route middleware:

    protected $routeMiddleware = [
        'auth' => \Illuminate\Auth\Middleware\Authenticate::class,
        ...

        'checksite' => \App\Http\Middleware\CheckSiteRole::class,
    ];


Add via middleware in routes file...: 

    Route::group(['middleware'=>['checksite'], 'as'=>'site.', 'namespace'=>'Site'], function()
    {
       ...
       // all routes inside this group whill use CheckSiteRole middleware
       ...
    });

