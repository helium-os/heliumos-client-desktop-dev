import React, { useMemo, useCallback, memo } from 'react';
import { Input, Divider } from 'antd';
import SectionLayout from '../common/SectionLayout';
import PanelLayout from '../common/PanelLayout';
import { Step, BaseTabContentProps } from '@/components/install-process/data.d';
import StoreConfigList, { ModeType } from '../common/StoreConfigList';
import { RootState, useAppDispatch, useAppSelector } from '@/store';
import { setAdminPassword } from '@/store/slices/installConfigSlice';
import useStyles from './style';
import FooterButtons from '../common/FooterButtons';
export interface IProps extends BaseTabContentProps {}

const InstallConfig: React.FC<IProps> = ({ onStep, ...restProps }) => {
    const { styles } = useStyles();

    const dispatch = useAppDispatch();
    const adminPassword = useAppSelector((state: RootState) => state.installConfig.adminPassword);

    const changeAdminPassword = useCallback(
        (password: string) => {
            dispatch(setAdminPassword(password));
        },
        [dispatch],
    );

    // admin密码更改
    const onAdminChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const { value } = e.target;
        changeAdminPassword(value.trim());
    };

    const footerButtons = useMemo(
        () => (
            <FooterButtons
                cancelButton={{
                    text: '返回',
                    onClick: () => onStep?.(Step.Back),
                }}
                primaryButton={{
                    text: '下一步',
                    disabled: !adminPassword,
                    onClick: () => onStep?.(Step.Next),
                }}
            />
        ),
        [adminPassword, onStep],
    );

    return (
        <PanelLayout footer={footerButtons} {...restProps}>
            <SectionLayout title="admin 密码">
                <Input placeholder="admin 密码" value={adminPassword} onChange={onAdminChange} />
            </SectionLayout>
            <Divider />
            <StoreConfigList type={ModeType.Write} />
        </PanelLayout>
    );
};

export default memo(InstallConfig);
