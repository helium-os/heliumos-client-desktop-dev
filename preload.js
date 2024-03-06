const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('versions', {
    lock: 'false',
    name: () => ipcRenderer.invoke('getUserValue', 'name'),
    password: () => ipcRenderer.invoke('getUserValue', 'password'),
    setuserInfo: (value) => ipcRenderer.send('setuserInfo', value),
    getDNS: () => ipcRenderer.invoke('getUserValue', 'DNS'),
    clearInfo: (res) => ipcRenderer.send('clearInfo', res),
    getValue: (res) => ipcRenderer.invoke('getUserValue', res),
    getDbValue: () => ipcRenderer.invoke('getDbValue'),
    getMessage: (name, fun) => ipcRenderer.on(name, fun),
    sendMethod: (name) => ipcRenderer.send(name),
    invokMethod: (name, value) => ipcRenderer.invoke(name, value),
    loadLocalFont: () => ipcRenderer.invoke('loadLocalFont'),
    openExternal: (url) => ipcRenderer.send('openExternalUrl', url),
    loadURL: (url) => ipcRenderer.send('loadURL', url),
    loadKeycloakLogin: (orgId) => ipcRenderer.send('loadKeycloakLogin', orgId),
    switchModeType: (modeType, orgId) => ipcRenderer.send('switchModeType', modeType, orgId),
    getBinaryPath: (id) => ipcRenderer.invoke('getBinaryPath', id),
    getBinaryVersion: (path, id) => ipcRenderer.invoke('getBinaryVersion', path, id),
    getDefaultKubeConfig: () => ipcRenderer.invoke('getDefaultKubeConfig'),
    getClusterConfig: (config) => ipcRenderer.invoke('getClusterConfig', config),
    installHeliumos: (configObj) => ipcRenderer.invoke('installHeliumos', configObj),
    getInstallStatus: (orgId) => ipcRenderer.invoke('getInstallStatus', orgId),
});
