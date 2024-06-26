// 当前项目的所有页面路径
const pageToPathMap = {
    login: '/login/alias',
    loginByAlias: '/login/alias',
    loginByIp: '/login/ip',
    userList: '/user-list',
    installMode: '/install-mode',
    installProcess: '/install-process',
};

const pagePaths = Object.values(pageToPathMap).map((path) => path);

module.exports = {
    pageToPathMap,
    pagePaths,
};
