const fs = require('fs')
const storage = require("electron-json-storage");
const dirCache = {};
const _ = require('lodash');
const { dialog } = require("electron");
const path = require("path");
const log = require('electron-log');
const electronLocalshortcut = require('electron-localshortcut');
let updateDownloaded = false;
//存入数据
setDataSourse = (data, filePath = './data.json', en = true) => {

  if (!fs.existsSync(filePath)) {
    writeFileByUser(filePath)
  }
  fs.writeFileSync(
    filePath,
    data,
    {
      encoding: "utf-8"
    }
  );
}
//
function writeFileByUser(filePath) {
  mkdir(filePath);
  fs.appendFile(filePath, '', 'utf8', function (err) {
    if (err) {
      console.log(err);
    } else {
      console.log('appendFile')
    }
  })
}

function mkdir(filePath) {
  const arr = filePath.split('/');
  let dir = arr[0];
  for (let i = 1; i < arr.length; i++) {
    if (!dirCache[dir] && !fs.existsSync(dir)) {
      dirCache[dir] = true;
      fs.mkdirSync(dir);
    }
    dir = dir + '/' + arr[i];
  }
  fs.writeFileSync(filePath, '')
}

//自动更新
AutoUpdater = (autoUpdater) => {
  let checkingForUpdate = false;
  autoUpdater.logger = log
  //要想使用自动更新，不能配置DNS解析
  autoUpdater.setFeedURL("https://heliumos-client.oss-cn-beijing.aliyuncs.com/desktop/releases/");
  autoUpdater.autoDownload = false
  autoUpdater.checkForUpdates();
  autoUpdater.on('update-not-available', () => {
    if (!checkingForUpdate) {
    // 原分支没有更新，切换到 GitHub Releases 的更新
      checkingForUpdate = true;
      autoUpdater.setFeedURL({
        provider: 'github',
        owner: 'helium-os',
        repo: "heliumos-client-desktop",
        releaseType: "release"
      });
      setTimeout(()=>autoUpdater.checkForUpdates(),5000)
    }
  });

  // 处理发现更新事件
  autoUpdater.on('update-available', () => {
    autoUpdater.downloadUpdate()
  });

  // 处理没有更新的事件
  autoUpdater.on('update-not-available', () => {
    log.info('No update available.');
  });

  // 处理更新下载进度事件
  autoUpdater.on('download-progress', (progressObj) => {
    log.info('Download progress:', progressObj);
  });

  // 处理更新下载完成事件
  autoUpdater.on('update-downloaded', () => {
    if (!updateDownloaded) {
      updateDownloaded = true
      dialog.showMessageBox({
        title: '更新 Helium OS',
        message: '发现新版本，重新启动 Helium OS 即可更新完成。',
        buttons: ['重新启动以更新', '取消']
      }).then((res) => {
        updateDownloaded = false
        if (res.response == 0) {
          autoUpdater.quitAndInstall()
        }
      })
    }
  });

  // 处理更新错误事件
  autoUpdater.on('error', (err) => {
    console.error('Error while checking for updates:', err);
    if (!checkingForUpdate) {
      // 更新失败，切换到 GitHub Releases 的更新
      checkingForUpdate = true;
      autoUpdater.setFeedURL({
        provider: 'github',
        owner: 'helium-os',
        repo: "heliumos-client-desktop",
        releaseType: "release"
      });
      // 再次检查更新
      autoUpdater.checkForUpdates()
    }
  });
}

// 定时更新
function AutoUpdaterInterval(autoUpdater, hour = 6, updateNow = true) {
  let timerId;

  if (updateNow) {
    AutoUpdater(autoUpdater);
  }

  // 定时函数
  function myTask() {
    AutoUpdater(autoUpdater);
  }

  // 设置定时器
  timerId = setInterval(myTask, hour * 60 * 60 * 1000);

  // 返回一个函数来清除定时器
  return function clearTimer() {
    clearInterval(timerId);
  };
}

macShortcutKeyFailure = (win) => {
  if (process.platform === 'darwin') {
    let contents = win.webContents
    electronLocalshortcut.register(win, 'CommandOrControl+C', () => {
      if (win && !win.isDestroyed()) {
        console.log('注册复制快捷键成功')
        contents && contents?.copy()
      }
    })

    electronLocalshortcut.register(win, 'CommandOrControl+V', () => {
      if (win && !win.isDestroyed()) {
        console.log('注册粘贴快捷键成功')
        contents && contents?.paste()
      }
    })

    electronLocalshortcut.register(win, 'CommandOrControl+X', () => {
      if (win && !win.isDestroyed()) {
        console.log('注册剪切快捷键成功')
        contents && contents?.cut()
      }
    })

    electronLocalshortcut.register(win, 'CommandOrControl+A', () => {
      if (win && !win.isDestroyed()) {
        console.log('注册全选快捷键成功')
        contents && contents?.selectAll()
      }
    })
  }
}
//多开
multipleOpen = (app, BrowserWindow, createWindow, mul = false) => {
  if (mul) {
    createWindow();
  } else {
    if (!app.requestSingleInstanceLock()) {
      app.quit();
      return;
    }
    createWindow();
    app.on("active", () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  }
}
//获取stroage数据
getStorageData = (data = 'data') => {
  let res
  let promise = new Promise((resolve) => {
    res = resolve;
  });
  storage.get(data, function (error, datas) {
    res(datas)
  });
  return promise
}

function getNewValue(value, oldValue) {
  if (value === null) {
    return value;
  } else if (Array.isArray(value)) {
    return value;
  } else if (typeof value === 'object') {
    return { ...oldValue || {}, ...value };
  } else {
    return value;
  }
}
//存放stroage数据
setStorageData = async (datas = 'data', arg, routeList = []) => {
  let data = await getStorageData(datas)
  data = data || {}
  if (routeList.length == 0) {
    data = _.merge({}, data, arg);
  } else {
    let setData = data
    for (let i = 0; i < routeList.length - 1; i++) {
      if (!setData[routeList[i]]) {
        setData[routeList[i]] = {}
      }
      setData = setData[routeList[i]]
    }
    setData[routeList[routeList.length - 1]] = getNewValue(arg, setData[routeList[routeList.length - 1]] || {})
  }

  storage.set(datas, data);
}
//判断路径
findPath = (keyList = [], filePath = __dirname) => {
  var res
  keyList.forEach(item => {
    if (fs.existsSync(path.join(filePath, item))) {
      res = item
    }
  })
  return res
}




askForMediaAccess = (data = [true, true]) => {
  let MediaList = ['microphone', 'camera'].filter((item, index) => data[index])
  return new Promise((resolve, reject) => {
    if (os.platform() === 'darwin') {
      // 使用 Promise.all 来等待两个权限请求完成
      Promise.all([
        ...MediaList.map(item => systemPreferences.askForMediaAccess(item))
      ])
        .then((res) => {
          resolve(res); // 用户拒绝了其中一个或两者的访问权限
        })
        .catch((error) => {
          reject(error); // 处理错误
        });
    } else {
      // 如果不在 macOS 上，直接返回 true（模拟已授权）
      resolve(data);
    }
  });
};

module.exports = {
  setDataSourse,
  AutoUpdater,
  AutoUpdaterInterval,
  macShortcutKeyFailure,
  multipleOpen,
  getStorageData,
  setStorageData,
  askForMediaAccess,
  findPath
};