import { useState, useEffect, useMemo } from 'react';
import dynamic from 'next/dynamic';
import { useRouter } from 'next/router';
import { Form, message } from 'antd';
import BgLayout from '@/components/structure/BgLayout';
import MyInput from '@/components/common/MyInput';
import useStyles from './style';
import { ModeType } from '@/utils/data';
import SwitchModeType from '@/components/structure/SwitchModeType';

export default function Page() {
    const router = useRouter();

    const { styles } = useStyles();

    const [form] = Form.useForm();
    const [messageApi, contextHolder] = message.useMessage();

    const [spinning, setSpinning] = useState(false);
    const [value, setValue] = useState('');
    const [back, setBack] = useState(true);
    const onFinish = async (values) => {
        if (values?.usePoint) {
            let orgList = [];
            if (window?.versions) {
                orgList = await window?.versions?.getDbValue();
                if (orgList.find((item) => item?.alias == values?.usePoint)) {
                    await window?.versions?.setuserInfo({
                        org: values?.usePoint,
                        orgId: orgList.filter((item) => item?.alias == values?.usePoint)[0]?.id,
                        name: null,
                        autoLogin: null,
                    });
                } else {
                    messageApi.open({
                        type: 'error',
                        content: '没有该组织',
                    });
                    return;
                }
            }

            window.versions?.loadKeycloakLogin(orgList.filter((item) => item?.alias == values?.usePoint)[0]?.id);
        }
    };
    const addObverser = async () => {
        if (window?.versions) {
            await window?.versions?.getMessage('change-env', (event, arg) => {
                form.setFieldsValue({ usePoint: '' });
                setBack(false);
            });
            let name = await window?.versions?.invokMethod('getUserValue', 'name');
            setBack(!!name);
        }
    };
    useEffect(() => {
        addObverser();
    }, []);

    return (
        <>
            {contextHolder}
            <BgLayout className={styles.loginPageContainer}>
                <Form form={form} onFinish={onFinish} layout={'vertical'}>
                    <div className="account">
                        <div className="accountTitle">组织别名</div>
                        <div className="accountContent">请输入组织别名跳转到组织的登录界面</div>
                        <Form.Item name="usePoint" label={''}>
                            <MyInput
                                onChange={(e) => {
                                    setValue(e);
                                }}
                                rules={{ required: true, message: '请输入组织别名' }}
                                spinning={spinning}
                                form={form}
                                name="usePoint"
                                title="组织别名"
                                allowclear={true}
                                placeholder="请输入组织别名"
                            />
                        </Form.Item>
                        <input className="loginButton" type="submit" disabled={!value} value={'下一步'} />
                    </div>
                </Form>
                {window.history.length > 1 && back && (
                    <div
                        className="goBack"
                        onClick={() => {
                            console.log(window.history.length);
                            window.history.back();
                        }}
                    >
                        返回
                    </div>
                )}
            </BgLayout>
            <SwitchModeType defaultModeType={ModeType.Normal} />
        </>
    );
}