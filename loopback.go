// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

// +build linux darwin

package loopback

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"golang.org/x/net/context"
)

const (
	attrValidDuration = 1 * time.Second
)

type wrapErr struct {
	error // The original error.
	errno fuse.Errno
}

var _ fuse.ErrorNumber = wrapErr{}

func (err wrapErr) Cause() error {
	return err.error // Allow unwrapping.
}

func (err wrapErr) Errno() fuse.Errno {
	return err.errno
}

func getErrno(err error) fuse.Errno {
	switch e := err.(type) {
	case fuse.Errno:
		return e
	case *os.SyscallError:
		return getErrno(e.Err)
	case *os.PathError:
		return getErrno(e.Err)
	case *os.LinkError:
		return getErrno(e.Err)
	case syscall.Errno:
		return fuse.Errno(e)
	// These two interface checks go last:
	case fuse.ErrorNumber:
		return e.Errno()
	case interface{ Cause() error }:
		return getErrno(e.Cause())
	}
	return fuse.DefaultErrno
}

func translateError(err error) error {
	if err == nil {
		return nil
	}
	return wrapErr{err, getErrno(err)}
}

// FS is the filesystem root
type FS struct {
	rootPath string
	logger   interface {
		Print(v ...interface{})
		Printf(format string, v ...interface{})
	}

	nlock sync.Mutex
	nodes map[string][]*Node // realPath -> nodes
}

type noLog struct {
}

func (noLog) Print(v ...interface{}) {
}

func (noLog) Printf(format string, v ...interface{}) {
}

func New(rootPath string) *FS {
	return &FS{
		rootPath: rootPath,
		logger:   noLog{},
		nodes:    make(map[string][]*Node),
	}
}

func (f *FS) SetLogger(logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
}) {
	f.logger = logger
}

func (f *FS) newNode(n *Node) {
	rp := n.getRealPath()

	f.nlock.Lock()
	defer f.nlock.Unlock()
	f.nodes[rp] = append(f.nodes[rp], n)
}

func (f *FS) nodeRenamed(oldPath string, newPath string) {
	f.nlock.Lock()
	defer f.nlock.Unlock()
	f.nodes[newPath] = append(f.nodes[newPath], f.nodes[oldPath]...)
	delete(f.nodes, oldPath)
	for _, n := range f.nodes[newPath] {
		n.updateRealPath(newPath)
	}
}

func (f *FS) forgetNode(n *Node) {
	f.nlock.Lock()
	defer f.nlock.Unlock()
	nodes, ok := f.nodes[n.realPath]
	if !ok {
		return
	}

	found := -1
	for i, node := range nodes {
		if node == n {
			found = i
			break
		}
	}

	if found > -1 {
		nodes = append(nodes[:found], nodes[found+1:]...)
	}
	if len(nodes) == 0 {
		delete(f.nodes, n.realPath)
	} else {
		f.nodes[n.realPath] = nodes
	}
}

// Root implements fs.FS interface for *FS
func (f *FS) Root() (n fs.Node, err error) {
	defer func() { f.logger.Printf("FS.Root(): %#+v error=%v", n, err) }()
	nn := &Node{realPath: f.rootPath, isDir: true, fs: f}
	f.newNode(nn)
	return nn, nil
}

var _ fs.FSStatfser = (*FS)(nil)

// Statfs implements fs.FSStatfser interface for *FS
func (f *FS) Statfs(ctx context.Context,
	req *fuse.StatfsRequest, resp *fuse.StatfsResponse) (err error) {
	defer func() { f.logger.Printf("FS.Statfs(): error=%v", err) }()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(f.rootPath, &stat); err != nil {
		return translateError(err)
	}
	resp.Blocks = stat.Blocks
	resp.Bfree = stat.Bfree
	resp.Bavail = stat.Bavail
	resp.Files = stat.Files
	resp.Ffree = stat.Ffree
	resp.Bsize = uint32(stat.Bsize)
	resp.Namelen = 255 // (Maximum file name length?)
	resp.Frsize = 8    // (Fragment size...)

	return nil
}

// Handle represent an open file or directory
type Handle struct {
	fs        *FS
	reopener  func() (*os.File, error)
	forgetter func()

	f *os.File
}

var _ fs.HandleFlusher = (*Handle)(nil)

// Flush implements fs.HandleFlusher interface for *Handle
func (h *Handle) Flush(ctx context.Context,
	req *fuse.FlushRequest) (err error) {
	defer func() { h.fs.logger.Printf("Handle(%s).Flush(): error=%v", h.f.Name(), err) }()
	err = translateError(h.f.Sync())
	if errnum, _ := err.(fuse.ErrorNumber); errnum != nil {
		if syscall.Errno(errnum.Errno()) == syscall.EINVAL {
			// Clear error if invalid argument, some files don't like fsync.
			err = nil
		}
	}
	return err
}

/*
var _ fs.HandleReadAller = (*Handle)(nil)

// ReadAll implements fs.HandleReadAller interface for *Handle
func (h *Handle) ReadAll(ctx context.Context) (d []byte, err error) {
	defer func() {
		h.fs.logger.Printf("Handle(%s).ReadAll(): error=%v",
			h.f.Name(), err)
	}()
	data, err := ioutil.ReadAll(h.f)
	return data, translateError(err)
}
*/

var _ fs.HandleReadDirAller = (*Handle)(nil)

// ReadDirAll implements fs.HandleReadDirAller interface for *Handle
func (h *Handle) ReadDirAll(ctx context.Context) (
	dirs []fuse.Dirent, err error) {
	defer func() {
		h.fs.logger.Printf("Handle(%s).ReadDirAll(): %#+v error=%v",
			h.f.Name(), dirs, err)
	}()
	fis, err := h.f.Readdir(0)
	if err != nil {
		return nil, translateError(err)
	}

	// Readdir() reads up the entire dir stream but never resets the pointer.
	// Consequently, when Readdir is called again on the same *File, it gets
	// nothing. As a result, we need to close the file descriptor and re-open it
	// so next call would work.
	if err = h.f.Close(); err != nil {
		return nil, translateError(err)
	}
	if h.f, err = h.reopener(); err != nil {
		return nil, translateError(err)
	}

	return getDirentsWithFileInfos(fis), nil
}

var _ fs.HandleReader = (*Handle)(nil)

// Read implements fs.HandleReader interface for *Handle
func (h *Handle) Read(ctx context.Context,
	req *fuse.ReadRequest, resp *fuse.ReadResponse) (err error) {
	defer func() {
		h.fs.logger.Printf("Handle(%s).Read(): error=%v",
			h.f.Name(), err)
	}()

	resp.Data = make([]byte, req.Size)
	n, err := h.f.ReadAt(resp.Data, req.Offset)
	resp.Data = resp.Data[:n]
	if err != nil && n == 0 && err != io.EOF {
		return translateError(err)
	}
	return nil
}

var _ fs.HandleReleaser = (*Handle)(nil)

// Release implements fs.HandleReleaser interface for *Handle
func (h *Handle) Release(ctx context.Context,
	req *fuse.ReleaseRequest) (err error) {
	defer func() {
		h.fs.logger.Printf("Handle(%s).Release(): error=%v",
			h.f.Name(), err)
	}()
	if h.forgetter != nil {
		h.forgetter()
	}
	return translateError(h.f.Close())
}

var _ fs.HandleWriter = (*Handle)(nil)

// Write implements fs.HandleWriter interface for *Handle
func (h *Handle) Write(ctx context.Context,
	req *fuse.WriteRequest, resp *fuse.WriteResponse) (err error) {
	defer func() {
		h.fs.logger.Printf("Handle(%s).Write(): error=%v",
			h.f.Name(), err)
	}()

	n, err := h.f.WriteAt(req.Data, req.Offset)
	resp.Size = n
	if n != 0 {
		return nil
	}
	return translateError(err)
}

// Node is the node for both directories and files
type Node struct {
	fs *FS

	rpLock   sync.RWMutex
	realPath string

	isDir bool

	lock     sync.RWMutex
	flushers map[*Handle]bool
}

func (n *Node) IsDir() bool {
	return n.isDir
}

func (n *Node) getRealPath() string {
	n.rpLock.RLock()
	defer n.rpLock.RUnlock()
	return n.realPath
}

func (n *Node) GetRealPath() string {
	return n.getRealPath()
}

func (n *Node) updateRealPath(realPath string) {
	n.rpLock.Lock()
	defer n.rpLock.Unlock()
	n.realPath = realPath
}

var _ fs.NodeAccesser = (*Node)(nil)

// Access implements fs.NodeAccesser interface for *Node
func (n *Node) Access(ctx context.Context, a *fuse.AccessRequest) (err error) {
	defer func() {
		n.fs.logger.Printf("%s.Access(%o): error=%v", n.getRealPath(), a.Mask, err)
	}()
	fi, err := os.Lstat(n.getRealPath())
	if err != nil {
		return translateError(err)
	}
	if a.Mask&uint32(fi.Mode()>>6) != a.Mask {
		return fuse.EPERM
	}
	return nil
}

// Attr implements fs.Node interface for *Dir
func (n *Node) Attr(ctx context.Context, a *fuse.Attr) (err error) {
	defer func() { n.fs.logger.Printf("%s.Attr(): %#+v error=%v", n.getRealPath(), a, err) }()
	fi, err := os.Lstat(n.getRealPath())
	if err != nil {
		return translateError(err)
	}

	fillAttrWithFileInfo(a, fi)

	return nil
}

// Lookup implements fs.NodeRequestLookuper interface for *Node
func (n *Node) Lookup(ctx context.Context,
	name string) (ret fs.Node, err error) {
	defer func() {
		n.fs.logger.Printf("%s.Lookup(%s): %#+v error=%v",
			n.getRealPath(), name, ret, err)
	}()

	if !n.isDir {
		return nil, fuse.ENOTSUP
	}

	p := filepath.Join(n.getRealPath(), name)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, translateError(err)
	}

	var nn *Node
	if fi.IsDir() {
		nn = &Node{realPath: p, isDir: true, fs: n.fs}
	} else {
		nn = &Node{realPath: p, isDir: false, fs: n.fs}
	}

	n.fs.newNode(nn)
	return nn, nil
}

func getDirentsWithFileInfos(fis []os.FileInfo) (dirs []fuse.Dirent) {
	for _, fi := range fis {
		stat := fi.Sys().(*syscall.Stat_t)
		var tp fuse.DirentType

		mtype := fi.Mode() & os.ModeType
		switch {
		case mtype&os.ModeSymlink != 0:
			tp = fuse.DT_Link
		case mtype&os.ModeDir != 0:
			tp = fuse.DT_Dir
		case mtype == 0:
			tp = fuse.DT_File
		default:
			//panic("unsupported dirent type")
			continue
		}

		dirs = append(dirs, fuse.Dirent{
			Inode: stat.Ino,
			Name:  fi.Name(),
			Type:  tp,
		})
	}

	return dirs
}

func fuseOpenFlagsToOSFlagsAndPerms(
	f fuse.OpenFlags) (flag int, perm os.FileMode) {
	flag = int(f & fuse.OpenAccessModeMask)
	if f&fuse.OpenAppend != 0 {
		perm |= os.ModeAppend
	}
	if f&fuse.OpenCreate != 0 {
		flag |= os.O_CREATE
	}
	if f&fuse.OpenDirectory != 0 {
		perm |= os.ModeDir
	}
	if f&fuse.OpenExclusive != 0 {
		perm |= os.ModeExclusive
	}
	if f&fuse.OpenNonblock != 0 {
		//x.logger.Printf("fuse.OpenNonblock is set in OpenFlags but ignored")
	}
	if f&fuse.OpenSync != 0 {
		flag |= os.O_SYNC
	}
	if f&fuse.OpenTruncate != 0 {
		flag |= os.O_TRUNC
	}

	return flag, perm
}

func (n *Node) rememberHandle(h *Handle) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.flushers == nil {
		n.flushers = make(map[*Handle]bool)
	}
	n.flushers[h] = true
}

func (n *Node) forgetHandle(h *Handle) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.flushers == nil {
		return
	}
	delete(n.flushers, h)
}

var _ fs.NodeOpener = (*Node)(nil)

// Open implements fs.NodeOpener interface for *Node
func (n *Node) Open(ctx context.Context,
	req *fuse.OpenRequest, resp *fuse.OpenResponse) (h fs.Handle, err error) {
	flags, perm := fuseOpenFlagsToOSFlagsAndPerms(req.Flags)
	defer func() {
		n.fs.logger.Printf("%s.Open(): %o %o error=%v",
			n.getRealPath(), flags, perm, err)
	}()

	opener := func() (*os.File, error) {
		return os.OpenFile(n.getRealPath(), flags, perm)
	}

	f, err := opener()
	if err != nil {
		return nil, translateError(err)
	}

	handle := &Handle{fs: n.fs, f: f, reopener: opener}
	n.rememberHandle(handle)
	handle.forgetter = func() {
		n.forgetHandle(handle)
	}
	return handle, nil
}

var _ fs.NodeCreater = (*Node)(nil)

// Create implements fs.NodeCreater interface for *Node
func (n *Node) Create(
	ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (
	fsn fs.Node, fsh fs.Handle, err error) {
	flags, _ := fuseOpenFlagsToOSFlagsAndPerms(req.Flags)
	name := filepath.Join(n.getRealPath(), req.Name)
	defer func() {
		n.fs.logger.Printf("%s.Create(%s): %o %o error=%v",
			n.getRealPath(), name, flags, req.Mode, err)
	}()

	opener := func() (f *os.File, err error) {
		return os.OpenFile(name, flags, req.Mode)
	}

	f, err := opener()
	if err != nil {
		return nil, nil, translateError(err)
	}

	h := &Handle{fs: n.fs, f: f, reopener: opener}

	node := &Node{
		realPath: filepath.Join(n.getRealPath(), req.Name),
		isDir:    req.Mode.IsDir(),
		fs:       n.fs,
	}
	node.rememberHandle(h)
	h.forgetter = func() {
		node.forgetHandle(h)
	}
	n.fs.newNode(node)
	return node, h, nil
}

var _ fs.NodeMkdirer = (*Node)(nil)

// Mkdir implements fs.NodeMkdirer interface for *Node
func (n *Node) Mkdir(ctx context.Context,
	req *fuse.MkdirRequest) (created fs.Node, err error) {
	defer func() { n.fs.logger.Printf("%s.Mkdir(%s): error=%v", n.getRealPath(), req.Name, err) }()
	name := filepath.Join(n.getRealPath(), req.Name)
	if err = os.Mkdir(name, req.Mode); err != nil {
		return nil, translateError(err)
	}
	nn := &Node{realPath: name, isDir: true, fs: n.fs}
	n.fs.newNode(nn)
	return nn, nil
}

var _ fs.NodeRemover = (*Node)(nil)

// Remove implements fs.NodeRemover interface for *Node
func (n *Node) Remove(ctx context.Context, req *fuse.RemoveRequest) (err error) {
	name := filepath.Join(n.getRealPath(), req.Name)
	defer func() { n.fs.logger.Printf("%s.Remove(%s): error=%v", n.getRealPath(), name, err) }()
	return translateError(os.Remove(name))
}

var _ fs.NodeFsyncer = (*Node)(nil)

// Fsync implements fs.NodeFsyncer interface for *Node
func (n *Node) Fsync(ctx context.Context, req *fuse.FsyncRequest) (err error) {
	defer func() { n.fs.logger.Printf("%s.Fsync(): error=%v", n.getRealPath(), err) }()
	n.lock.RLock()
	defer n.lock.RUnlock()
	for h := range n.flushers {
		return translateError(h.f.Sync())
	}
	return fuse.EIO
}

var _ fs.NodeSetattrer = (*Node)(nil)

// Setattr implements fs.NodeSetattrer interface for *Node
func (n *Node) Setattr(ctx context.Context,
	req *fuse.SetattrRequest, resp *fuse.SetattrResponse) (err error) {
	defer func() {
		n.fs.logger.Printf("%s.Setattr(valid=%x): error=%v", n.getRealPath(), req.Valid, err)
	}()
	if req.Valid.Size() {
		if err = syscall.Truncate(n.getRealPath(), int64(req.Size)); err != nil {
			return translateError(err)
		}
	}

	if req.Valid.Mtime() {
		var tvs [2]syscall.Timeval
		if !req.Valid.Atime() {
			tvs[0] = tToTv(time.Now())
		} else {
			tvs[0] = tToTv(req.Atime)
		}
		tvs[1] = tToTv(req.Mtime)
	}

	if req.Valid.Handle() {
		n.fs.logger.Printf("%s.Setattr(): unhandled request: req.Valid.Handle() == true",
			n.getRealPath())
	}

	if req.Valid.Mode() {
		if err = os.Chmod(n.getRealPath(), req.Mode); err != nil {
			return translateError(err)
		}
	}

	if req.Valid.Uid() || req.Valid.Gid() {
		if req.Valid.Uid() && req.Valid.Gid() {
			if err = os.Chown(n.getRealPath(), int(req.Uid), int(req.Gid)); err != nil {
				return translateError(err)
			}
		}
		fi, err := os.Lstat(n.getRealPath())
		if err != nil {
			return translateError(err)
		}
		s := fi.Sys().(*syscall.Stat_t)
		if req.Valid.Uid() {
			if err = os.Chown(n.getRealPath(), int(req.Uid), int(s.Gid)); err != nil {
				return translateError(err)
			}
		} else {
			if err = os.Chown(n.getRealPath(), int(s.Uid), int(req.Gid)); err != nil {
				return translateError(err)
			}
		}
	}

	if err = n.setattrPlatformSpecific(ctx, req, resp); err != nil {
		return translateError(err)
	}

	fi, err := os.Lstat(n.getRealPath())
	if err != nil {
		return translateError(err)
	}

	fillAttrWithFileInfo(&resp.Attr, fi)

	return nil
}

var _ fs.NodeRenamer = (*Node)(nil)

// Rename implements fs.NodeRenamer interface for *Node
func (n *Node) Rename(ctx context.Context,
	req *fuse.RenameRequest, newDir fs.Node) (err error) {
	np := filepath.Join(newDir.(*Node).getRealPath(), req.NewName)
	op := filepath.Join(n.getRealPath(), req.OldName)
	defer func() {
		n.fs.logger.Printf("%s.Rename(%s->%s): error=%v",
			n.getRealPath(), op, np, err)
	}()
	defer func() {
		if err == nil {
			n.fs.nodeRenamed(op, np)
		}
	}()
	return translateError(os.Rename(op, np))
}

var _ fs.NodeForgetter = (*Node)(nil)

// Forget implements fs.NodeForgetter interface for *Node
func (n *Node) Forget() {
	n.fs.forgetNode(n)
}

var _ fs.NodeReadlinker = (*Node)(nil)

// Readlink implements fs.NodeReadlinker interface for *Node
func (n *Node) Readlink(ctx context.Context, req *fuse.ReadlinkRequest) (string, error) {
	target, err := os.Readlink(n.getRealPath())
	return target, translateError(err)
}

var _ fs.NodeSymlinker = (*Node)(nil)

// Symlink implements fs.NodeSymlinker interface for *Node
func (n *Node) Symlink(ctx context.Context, req *fuse.SymlinkRequest) (fs.Node, error) {
	name := filepath.Join(n.getRealPath(), req.NewName)
	err := os.Symlink(req.Target, name)
	if err != nil {
		return nil, translateError(err)
	}
	return &Node{realPath: name, isDir: false, fs: n.fs}, nil
}
