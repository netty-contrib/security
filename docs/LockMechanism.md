# Lock Mechanism
Lock mechanism is an interface used to prevent unsafe ArrayList modification. 
This is because ArrayList are not thread-safe.
When we try to modify ArrayList and read at the same time, it will return in an exception.
To prevent this from happening and ensure smooth read operations, this feature is implemented.

## SafeListController
`SafeListController` is an abstract implementation of `LockMechanism` which uses ArrayList.
It holds 2 ArrayList, Main List and Copy List. Main List is primary list where we read elements
for binary search. Copy List is a temporary list which is used when `LockMechanism` is unlocked.

By default, new instance of `SafeListController` is locked. It will have no element in its ArrayList.
To begin modifying, we have to call `SafeListController#unlock` method. It will unlock the Lock
and copy elements from Main List to Copy List. Once Copy List has elements of Main List,
we can call `SafeListMechanism#add` to add elements into Copy List and delete elements from Copy List.
Once addition and removal is finished, we will call `SafeListController#lock` method. It will lock the Lock
and clear the Main List entirely and copy all elements from Copy List to Main List. Once done, it will
clear the Copy List and now entire modification process and now Main List is ready again for read operations
using binary search.
