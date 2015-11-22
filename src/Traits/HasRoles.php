<?php

namespace Spatie\Permission\Traits;

use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Contracts\Role;
use Spatie\Permission\Models\Role as RoleModel;

trait HasRoles
{
    use HasPermissions;
    use RefreshesPermissionCache;


    /**
     * Assign the given role to the user.
     *
     * @param string|Role $role
     *
     * @return Role
     */
    public function assignRole($role)
    {
        $role = $this->getStoredRole($role);
        $roles = $this->getUserRoles();
        if(array_search($role->_id,$roles) === false){
            $roles[] = $role->_id;
        }
        $this->roles = $roles;
        $this->save();
    }

    /**
     * Revoke the given role from the user.
     *
     * @param string|Role $role
     *
     * @return mixed
     */
    public function removeRole($role)
    {
        $role = $this->getStoredRole($role);
        $roles = $this->getUserRoles();

        $key = array_search($role->_id,$roles);
        if($key !== false){
            unset($roles[$key]);
        }

        $this->roles = $roles;
        $this->save();
    }

    /**
     * get users roles list.
     *
     * @return \Spatie\Permission\Models\Role
     */
    public function getRoles()
    {
        return RoleModel::whereIn('_id', $this->roles)->get();
    }

    /**
     * get array of user roles.
     *
     */
    public function getUserRoles(){
        $roles = [];
        if(is_array($this->roles)){
            $roles = $this->roles;
        }
        return $roles;
    }

    /**
     * Determine if the user has (one of) the given role(s).
     *
     * @param string|Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasRole($roles)
    {
        if(is_null($this->roles)){
            return false;
        }
        
        if (is_string($roles)) {
            $roleId = RoleModel::where('name', $roles)->first()->_id;
            return (array_search($roleId,$this->roles) !== false);
        }

        if ($roles instanceof Role) {
            return (array_search($roles->_id,$this->roles) !== false);

        }

        return (bool) !!$roles->intersect($this->roles)->count();
    }

    /**
     * Determine if the user has any of the given role(s).
     *
     * @param string|Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAnyRole($roles)
    {
        return $this->hasRole($roles);
    }

    /**
     * Determine if the user has all of the given role(s).
     *
     * @param string|Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAllRoles($roles)
    {
        if (is_string($roles)) {
            $roleId = RoleModel::where('name', $roles)->first()->_id;
            return (array_search($roleId,$this->roles) !== false);
        }

        if ($roles instanceof Role) {
            return (array_search($roles->_id,$this->roles) !== false);
        }

        $roles = collect()->make($roles)->map(function ($role) {
            return $role instanceof Role ? $role->_id : $role;
        });

        return $roles->intersect($this->roles) == $roles;
    }

    /**
     * Determine if the user may perform the given permission.
     *
     * @param Permission $permission
     *
     * @return bool
     */
    public function hasPermissionTo($permission)
    {
        if (is_string($permission)) {
            $permission = app(Permission::class)->findByName($permission);
        }

        return $this->hasDirectPermission($permission) || $this->hasPermissionViaRole($permission);
    }

    /**
     * @deprecated deprecated since version 1.0.1, use hasPermissionTo instead
     *
     * Determine if the user may perform the given permission.
     *
     * @param Permission $permission
     *
     * @return bool
     */
    public function hasPermission($permission)
    {
        return $this->hasPermissionTo($permission);
    }

    /**
     * Determine if the user has, via roles, has the given permission.
     *
     * @param Permission $permission
     *
     * @return bool
     */
    protected function hasPermissionViaRole(Permission $permission)
    {
        return $this->hasRole($permission->roles);
    }

    /**
     * Determine if the user has has the given permission.
     *
     * @param Permission $permission
     *
     * @return bool
     */
    protected function hasDirectPermission(Permission $permission)
    {
        if (is_string($permission)) {
            $permission = app(Permission::class)->findByName($permission);
        }

        return $this->permissions->contains('id', $permission->id);
    }

    /**
     * @param $role
     *
     * @return Role
     */
    protected function getStoredRole($role)
    {
        if (is_string($role)) {
            return app(Role::class)->findByName($role);
        }

        return $role;
    }
}
