import React from 'react';
import Icon from '@ant-design/icons';
import type { GetProps } from 'antd';

type CustomIconComponentProps = GetProps<typeof Icon>;

const EyeInVisibleOutlined = () => (
    <svg width="1em" height="1em" viewBox="0 0 20 13" fill="currentColor">
        <path d="M10.0728 12.4297C9.1613 12.4297 8.29769 12.318 7.48193 12.0947C6.67074 11.876 5.9165 11.5866 5.21924 11.2266C4.52653 10.862 3.90446 10.4609 3.35303 10.0234C2.8016 9.58594 2.32992 9.14844 1.93799 8.71094C1.54606 8.26888 1.24528 7.861 1.03564 7.4873C0.830566 7.10905 0.728027 6.80371 0.728027 6.57129C0.728027 6.36621 0.810059 6.10417 0.974121 5.78516C1.13818 5.46159 1.37516 5.1084 1.68506 4.72559C1.99951 4.34277 2.38005 3.9554 2.82666 3.56348C3.27783 3.16699 3.78825 2.79329 4.35791 2.44238L5.20557 3.29004C4.69971 3.59082 4.24398 3.90755 3.83838 4.24023C3.43734 4.57292 3.09326 4.89421 2.80615 5.2041C2.5236 5.514 2.30485 5.78971 2.1499 6.03125C1.99951 6.27279 1.92432 6.4528 1.92432 6.57129C1.92432 6.73079 2.02002 6.95866 2.21143 7.25488C2.40283 7.55111 2.67627 7.87923 3.03174 8.23926C3.39176 8.59473 3.81787 8.95475 4.31006 9.31934C4.80225 9.68392 5.3514 10.0212 5.95752 10.3311C6.56364 10.6364 7.21305 10.8825 7.90576 11.0693C8.59847 11.2562 9.3208 11.3496 10.0728 11.3496C10.533 11.3496 10.9797 11.3132 11.4126 11.2402C11.8455 11.1673 12.2648 11.0693 12.6704 10.9463L13.5659 11.8418C13.0373 12.0241 12.4813 12.1676 11.8979 12.2725C11.3146 12.3773 10.7062 12.4297 10.0728 12.4297ZM10.0728 0.712891C10.9933 0.712891 11.8615 0.824544 12.6772 1.04785C13.4976 1.2666 14.2541 1.55827 14.9468 1.92285C15.6395 2.28288 16.2593 2.68164 16.8062 3.11914C17.3576 3.55664 17.827 3.99642 18.2144 4.43848C18.6017 4.87598 18.8979 5.28385 19.103 5.66211C19.3081 6.03581 19.4106 6.33887 19.4106 6.57129C19.4106 6.77181 19.3309 7.0293 19.1714 7.34375C19.0164 7.6582 18.7909 8.00228 18.4946 8.37598C18.1984 8.74512 17.8361 9.12337 17.4077 9.51074C16.9839 9.89811 16.5031 10.2673 15.9653 10.6182L15.1245 9.77734C15.5985 9.48568 16.0246 9.18262 16.4028 8.86816C16.7811 8.55371 17.1047 8.24837 17.3735 7.95215C17.647 7.65137 17.8543 7.38249 17.9956 7.14551C18.1414 6.90397 18.2144 6.71257 18.2144 6.57129C18.2144 6.43457 18.1164 6.22493 17.9204 5.94238C17.729 5.65983 17.4556 5.33854 17.1001 4.97852C16.7446 4.61393 16.3208 4.24707 15.8286 3.87793C15.3364 3.50879 14.7873 3.16699 14.1812 2.85254C13.575 2.53353 12.9256 2.27832 12.2329 2.08691C11.5402 1.89095 10.8201 1.79297 10.0728 1.79297C9.64893 1.79297 9.24105 1.82487 8.84912 1.88867C8.46175 1.95247 8.07894 2.03906 7.70068 2.14844L6.79834 1.25293C7.3042 1.08431 7.82601 0.952148 8.36377 0.856445C8.90609 0.760742 9.47575 0.712891 10.0728 0.712891ZM10.0728 10.3994C9.53499 10.3994 9.03369 10.2992 8.56885 10.0986C8.104 9.89811 7.69613 9.6224 7.34521 9.27148C6.9943 8.91602 6.72087 8.50814 6.5249 8.04785C6.32894 7.58301 6.22868 7.09082 6.22412 6.57129C6.22412 6.26595 6.2583 5.97201 6.32666 5.68945C6.39502 5.40234 6.493 5.13118 6.62061 4.87598L11.7476 10.0029C11.4924 10.126 11.2235 10.224 10.9409 10.2969C10.6629 10.3652 10.3735 10.3994 10.0728 10.3994ZM13.5796 8.06836L8.56885 3.05762C8.79671 2.95736 9.03597 2.87988 9.28662 2.8252C9.54183 2.77051 9.80387 2.74316 10.0728 2.74316C10.6014 2.74316 11.0981 2.84115 11.563 3.03711C12.0278 3.23307 12.4357 3.50651 12.7866 3.85742C13.1375 4.20378 13.411 4.60938 13.6069 5.07422C13.8075 5.53906 13.9077 6.03809 13.9077 6.57129C13.9077 6.83561 13.8781 7.09538 13.8188 7.35059C13.7642 7.60124 13.6844 7.84049 13.5796 8.06836ZM15.3911 12.4912L3.95459 1.06836C3.85433 0.968099 3.8042 0.845052 3.8042 0.699219C3.8042 0.548828 3.85433 0.423503 3.95459 0.323242C4.05941 0.218424 4.18473 0.168294 4.33057 0.172852C4.48096 0.172852 4.60628 0.222982 4.70654 0.323242L16.1362 11.7461C16.241 11.8509 16.2957 11.9717 16.3003 12.1084C16.3049 12.2497 16.2502 12.3773 16.1362 12.4912C16.0314 12.6051 15.9061 12.6598 15.7603 12.6553C15.619 12.6507 15.4959 12.596 15.3911 12.4912Z" />
    </svg>
);

const EyeInVisibleOutlinedIcon = (props: Partial<CustomIconComponentProps>) => (
    <Icon component={EyeInVisibleOutlined} {...props} />
);

export default EyeInVisibleOutlinedIcon;